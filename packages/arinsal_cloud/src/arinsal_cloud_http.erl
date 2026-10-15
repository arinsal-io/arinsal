%% Admin HTTP API on 127.0.0.1, plain gen_tcp with `{packet, http_bin}`.
%%
%%   GET    /projects                          list
%%   GET    /projects/:tenant/:project         details with the backend info map
%%   PUT    /projects/:tenant/:project         body: release tar.gz, unpack and (re)start
%%   POST   /projects/:tenant/:project/stop
%%   POST   /projects/:tenant/:project/start
%%   GET    /projects/:tenant/:project/logs?n=100[&since=Seq][&format=text]
%%   DELETE /projects/:tenant/:project
%%
%% App env: admin_port (default 7000, 0 picks a free one), max_body_bytes (default 512 MiB).
%% There is no authentication: it listens on loopback only.
-module(arinsal_cloud_http).
-behaviour(gen_server).

-export([start_link/0, port/0]).
-export([route/2, handle/3, json_safe/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-type route() ::
    list
    | {get, binary(), binary()}
    | {deploy, binary(), binary()}
    | {start, binary(), binary()}
    | {stop, binary(), binary()}
    | {logs, binary(), binary()}
    | {delete, binary(), binary()}
    | not_found
    | method_not_allowed.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec port() -> inet:port_number().
port() ->
    gen_server:call(?MODULE, port).

%% Routing is pure: method and path segments in, an operation out.
-spec route(binary(), [binary()]) -> route().
route(Method, [<<"projects">>]) ->
    one_of(Method, [{<<"GET">>, list}]);
route(Method, [<<"projects">>, T, P]) ->
    one_of(Method, [{<<"GET">>, {get, T, P}}, {<<"PUT">>, {deploy, T, P}}, {<<"DELETE">>, {delete, T, P}}]);
route(Method, [<<"projects">>, T, P, <<"stop">>]) ->
    one_of(Method, [{<<"POST">>, {stop, T, P}}]);
route(Method, [<<"projects">>, T, P, <<"start">>]) ->
    one_of(Method, [{<<"POST">>, {start, T, P}}]);
route(Method, [<<"projects">>, T, P, <<"logs">>]) ->
    one_of(Method, [{<<"GET">>, {logs, T, P}}]);
route(_, _) ->
    not_found.

one_of(Method, Options) ->
    case lists:keyfind(Method, 1, Options) of
        {_, Route} -> Route;
        false -> method_not_allowed
    end.

%% Request in, {Status, ContentType, Body} out.
-spec handle(binary(), binary(), binary()) -> {pos_integer(), binary(), iodata()}.
handle(Method, Target, Body) ->
    case uri_string:parse(Target) of
        {error, _, _} ->
            json(400, #{error => bad_request});
        Uri ->
            Segments = binary:split(maps:get(path, Uri, <<>>), <<"/">>, [global, trim_all]),
            Query = case uri_string:dissect_query(maps:get(query, Uri, <<>>)) of
                {error, _, _} -> [];
                Pairs -> Pairs
            end,
            dispatch(route(Method, Segments), Query, Body)
    end.

dispatch(not_found, _, _) ->
    json(404, #{error => not_found});
dispatch(method_not_allowed, _, _) ->
    json(405, #{error => method_not_allowed});
dispatch(list, _, _) ->
    json(200, arinsal_cloud_projects:list());
dispatch({get, T, P}, _, _) ->
    reply(arinsal_cloud_projects:get(T, P));
dispatch({deploy, T, P}, _, Body) ->
    reply(arinsal_cloud_projects:deploy(T, P, Body));
dispatch({start, T, P}, _, _) ->
    reply(arinsal_cloud_projects:start(T, P));
dispatch({stop, T, P}, _, _) ->
    reply(arinsal_cloud_projects:stop(T, P));
dispatch({delete, T, P}, _, _) ->
    reply(arinsal_cloud_projects:delete(T, P));
dispatch({logs, T, P}, Query, _) ->
    N = int_param(<<"n">>, Query, 100),
    Since = int_param(<<"since">>, Query, 0),
    case arinsal_cloud_projects:logs(T, P, #{n => N, since => Since}) of
        {ok, Lines, Next} ->
            case proplists:get_value(<<"format">>, Query) of
                <<"text">> ->
                    {200, <<"text/plain; charset=utf-8">>, [[L, $\n] || L <- Lines]};
                _ ->
                    json(200, #{lines => Lines, next => Next})
            end;
        {error, _} = Error ->
            reply(Error)
    end.

int_param(Name, Query, Default) ->
    case proplists:get_value(Name, Query) of
        undefined -> Default;
        Value ->
            case string:to_integer(Value) of
                {Int, <<>>} when Int >= 0 -> Int;
                _ -> Default
            end
    end.

reply({ok, Value}) -> json(200, Value);
reply(ok) -> json(200, #{ok => true});
reply({error, Reason}) -> json(error_status(Reason), #{error => Reason}).

error_status(not_found) -> 404;
error_status(bad_name) -> 400;
error_status({bad_release, _}) -> 400;
error_status(no_release) -> 409;
error_status(busy) -> 409;
error_status(_) -> 500.

json(Status, Term) ->
    {Status, <<"application/json">>, [json:encode(json_safe(Term)), $\n]}.

%% Turns Erlang terms into something `json:encode/1` accepts.
-spec json_safe(term()) -> term().
json_safe(undefined) -> null;
json_safe(Term) when is_boolean(Term); is_integer(Term); is_float(Term); Term =:= null -> Term;
json_safe(Term) when is_atom(Term) -> atom_to_binary(Term);
json_safe(Term) when is_binary(Term) ->
    case unicode:characters_to_binary(Term) of
        Bin when is_binary(Bin) -> Bin;
        _ -> iolist_to_binary(io_lib:format("~0p", [Term]))
    end;
json_safe(Term) when is_map(Term) ->
    maps:fold(fun(K, V, Acc) -> Acc#{json_key(K) => json_safe(V)} end, #{}, Term);
json_safe(Term) when is_list(Term) ->
    case io_lib:printable_unicode_list(Term) andalso Term =/= [] of
        true -> unicode:characters_to_binary(Term);
        false -> try [json_safe(E) || E <- Term] catch _:_ -> format(Term) end
    end;
json_safe(Term) when is_tuple(Term) ->
    case tuple_to_list(Term) of
        [Tag | Rest] when is_atom(Tag), Rest =/= [] -> [json_safe(Tag) | [json_safe(E) || E <- Rest]];
        List -> [json_safe(E) || E <- List]
    end;
json_safe(Term) ->
    format(Term).

json_key(K) when is_binary(K) -> K;
json_key(K) when is_atom(K) -> atom_to_binary(K);
json_key(K) -> format(K).

format(Term) ->
    iolist_to_binary(io_lib:format("~0p", [Term])).

%% gen_server owning the listen socket

init([]) ->
    Port = application:get_env(arinsal_cloud, admin_port, 7000),
    Opts = [binary, {ip, {127, 0, 0, 1}}, {active, false}, {reuseaddr, true}, {backlog, 128},
            {packet, http_bin}],
    case gen_tcp:listen(Port, Opts) of
        {ok, Listen} ->
            {ok, Actual} = inet:port(Listen),
            Acceptor = spawn_link(fun() -> accept_loop(Listen) end),
            {ok, #{listen => Listen, port => Actual, acceptor => Acceptor}};
        {error, Reason} ->
            {stop, {listen_failed, Port, Reason}}
    end.

handle_call(port, _From, #{port := Port} = S) ->
    {reply, Port, S};
handle_call(_Request, _From, S) ->
    {reply, {error, badcall}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info(_Info, S) ->
    {noreply, S}.

terminate(_Reason, #{listen := Listen}) ->
    gen_tcp:close(Listen).

accept_loop(Listen) ->
    case gen_tcp:accept(Listen) of
        {ok, Sock} ->
            Pid = spawn(fun() -> receive go -> serve(Sock) end end),
            ok = gen_tcp:controlling_process(Sock, Pid),
            Pid ! go,
            accept_loop(Listen);
        {error, closed} ->
            ok;
        {error, _} ->
            accept_loop(Listen)
    end.

serve(Sock) ->
    try
        case request(Sock) of
            {ok, Method, Target, Body} ->
                {Status, Type, Out} = handle(Method, Target, Body),
                send(Sock, Status, Type, Out);
            {error, Status, Msg} ->
                {S, T, O} = json(Status, #{error => Msg}),
                send(Sock, S, T, O);
            closed ->
                ok
        end
    catch
        Class:Reason ->
            {S2, T2, O2} = json(500, #{error => format({Class, Reason})}),
            try send(Sock, S2, T2, O2) catch _:_ -> ok end
    after
        gen_tcp:close(Sock)
    end.

request(Sock) ->
    case gen_tcp:recv(Sock, 0, 30000) of
        {ok, {http_request, Method, {abs_path, Target}, _Vsn}} ->
            headers(Sock, method_bin(Method), Target, #{});
        {ok, {http_request, _, _, _}} ->
            {error, 400, bad_request};
        {ok, {http_error, _}} ->
            {error, 400, bad_request};
        {error, _} ->
            closed
    end.

headers(Sock, Method, Target, Headers) ->
    case gen_tcp:recv(Sock, 0, 30000) of
        {ok, {http_header, _, Name, _, Value}} ->
            headers(Sock, Method, Target, Headers#{header_name(Name) => Value});
        {ok, http_eoh} ->
            body(Sock, Method, Target, Headers);
        {ok, {http_error, _}} ->
            {error, 400, bad_request};
        {error, _} ->
            closed
    end.

body(Sock, Method, Target, Headers) ->
    Max = application:get_env(arinsal_cloud, max_body_bytes, 512 * 1024 * 1024),
    case string:to_integer(maps:get(<<"content-length">>, Headers, <<"0">>)) of
        {Len, _} when is_integer(Len), Len > Max ->
            {error, 413, body_too_large};
        {0, _} ->
            {ok, Method, Target, <<>>};
        {Len, _} when is_integer(Len), Len > 0 ->
            case maps:get(<<"expect">>, Headers, undefined) of
                undefined -> ok;
                _ -> gen_tcp:send(Sock, <<"HTTP/1.1 100 Continue\r\n\r\n">>)
            end,
            ok = inet:setopts(Sock, [{packet, raw}]),
            case gen_tcp:recv(Sock, Len, 120000) of
                {ok, Body} -> {ok, Method, Target, Body};
                {error, _} -> closed
            end;
        _ ->
            {error, 400, bad_content_length}
    end.

method_bin(Method) when is_atom(Method) -> atom_to_binary(Method);
method_bin(Method) when is_binary(Method) -> Method.

header_name(Name) when is_atom(Name) -> header_name(atom_to_binary(Name));
header_name(Name) when is_binary(Name) -> string:lowercase(Name).

send(Sock, Status, Type, Body) ->
    Bin = iolist_to_binary(Body),
    gen_tcp:send(Sock, [
        "HTTP/1.1 ", integer_to_list(Status), " ", reason(Status), "\r\n",
        "Content-Type: ", Type, "\r\n",
        "Content-Length: ", integer_to_list(byte_size(Bin)), "\r\n",
        "Connection: close\r\n\r\n",
        Bin
    ]).

reason(200) -> "OK";
reason(400) -> "Bad Request";
reason(404) -> "Not Found";
reason(405) -> "Method Not Allowed";
reason(409) -> "Conflict";
reason(413) -> "Payload Too Large";
reason(_) -> "Internal Server Error".
