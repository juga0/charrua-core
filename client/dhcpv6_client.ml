(* a variant type representing the current [state] of the client transaction.
   Represented states differ from the diagram presented in RFC2131 in the
   following ways:
   The earliest state is `Selecting`.  There is no representation of INIT-REBOOT,
   REBOOTING, or INIT.  Calls to `create` will generate a client in state
   `Selecting` with the corresponding `DHCP6SOLICIT` recorded, and that packet
   is exposed to the caller of `create`, who is responsible for sending it.
   There is no REBINDING state.  Clients which do not re-enter the `Bound` state
   from `Renewing` do not halt their network and re-enter the `Selecting` state.
   *)
type state  = | Soliciting of Dhcpv6_wire.pkt (* dhcpv6solicit sent *)
              | Requesting of (Dhcpv6_wire.pkt * Dhcpv6_wire.pkt) (* dhcpv6advertise input * dhcpv6request sent *)
              | Bound of Dhcpv6_wire.pkt (* dhcpv6reply received *)

(* `srcmac` will be used as the source of Ethernet frames,
   as well as the client identifier whenever one is required (e.g. padded with
   0x00 in the `chaddr` field of the BOOTP message).
   `request_options` will be sent in DHCP6SOLICIT and DHCP6REQUEST packets. *)
type t = {
  srcmac : Macaddr.t;
  request_options : Dhcpv6_wire.option_code list;
  state  : state;
}

type buffer = Cstruct.t

(* some fields are constant *)
module Constants = struct
  open Dhcpv6_wire
end

(* This are the options that Windows 10 uses in the PRL implement RFC7844.
   They are ordered by code number.
   TODO: There should be a variable in the configuration where the user
   specifies to use the Anonymity Profiles, and ignore any other option that
   would modify this static PRL.
   This PRL could be also reverted to the minimal one and be used only when
   using Anonymity Profiles.
*)
let default_requests =
  Dhcpv6_wire.([
    DNS_SERVERS;
    DOMAIN_LIST;
  ])

let pp fmt p =
  let pr = Dhcpv6_wire.pkt_to_string in
   let pp_state fmt = function
    | Soliciting pkt -> Format.fprintf fmt "SELECTING.  Generated %s" @@ pr pkt
    | Requesting (received, sent) -> Format.fprintf fmt
        "REQUESTING. Received %s, and generated response %s" (pr received) (pr sent)
    | Bound pkt -> Format.fprintf fmt "BOUND.  Received %s" @@ pr pkt
  in
  Format.fprintf fmt "%s: %a" (Macaddr.to_string p.srcmac) pp_state p.state

let lease {state; _} = match state with
  | Bound dhcpv6reply -> Some dhcpv6reply
  | Requesting _ | Soliciting _ -> None

let xid {state; _} =
  let open Dhcpv6_wire in
  match state with
  | Soliciting p -> p.xid
  | Requesting (_i, o) -> o.xid
  | Bound a -> a.xid

let make_request ~xid ~srcmac ~options () =
  let open Dhcpv6_wire in
  Constants.({
    op;
    xid;
    srcport = Dhcpv6_wire.client_port;
    dstport = Dhcpv6_wire.server_port;
    srcmac;
    srcip = Ipaddr.V6.of_string_exn("ff02::1:2");
    (* destinations should still be broadcast,
     * even though we have the necessary information to send unicast,
     * because there might be >1 DHCP server on the network.
     * those who we're not responding to should know that we're in a
     * transaction to accept another lease. *)
    dstmac = Macaddr.broadcast;
    dstip = Ipaddr.V6.of_string_exn("ff02::1:2");
    options;
  })

let offer t ~xid ~server_ip ~offer_options =
  let open Dhcpv6_wire in
  (* TODO: make sure the offer contains everything we expect before we accept it *)
  let options = [
    Message_type DHCP6REQUEST;
    Server_identifier server_ip;
  ] in
  let options =
    match t.request_options with
    | [] -> options (* if this is the case, the user explicitly requested it; honor that *)
    | _::_ -> (Parameter_requests t.request_options) :: options
  in
  make_request ~xid ~srcmac:t.srcmac ~options:options ()

let create ?with_xid ?requests srcmac =
  let open Constants in
  let open Dhcpv6_wire in
  let xid = match with_xid with
  | None -> Stdlibrandom.initialize (); Cstruct.BE.get_uint32 (Stdlibrandom.generate 4) 0
  | Some xid -> xid
  in
  let requests = match requests with
  | None | Some [] -> default_requests
  | Some requests -> requests
  in
  let pkt = {
    srcmac;
    dstmac = Macaddr.broadcast;
    (* FIXME *)
    (* let broadcast = Ipaddr.V6.of_string_exn("ff02::1:2") *)
    srcip = broadcast;
    dstip = broadcast; *)
    srcip = Ipaddr.V6.of_string_exn("ff02::1:2");
    dstip = Ipaddr.V6.of_string_exn("ff02::1:2");
    srcport = client_port;
    dstport = server_port;
    op;
    xid;
    (* which other fields?*)
    options = [
      Message_type DHCPV6SOLICIT;
      Client_id (Hwaddr srcmac);
      Parameter_requests requests;
    ];
  } in
  {srcmac; request_options = requests; state = Soliciting pkt},
    Dhcpv6_wire.buf_of_pkt pkt

let input t buf =
  let open Dhcpv6_wire in
  match pkt_of_buf buf (Cstruct.len buf) with
  | Error _ -> `Noop
  | Ok incoming ->
    if compare incoming.xid (xid t) = 0 then begin
    match find_message_type incoming.options, t.state with
    | None, _ -> `Noop
    | Some DHCP6ADVERTISE, Soliciting dhcpv6solicit ->
        let dhcpv6request = offer t
                          ~xid:dhcpv6solicit.xidin in
        `Response ({t with state = Requesting (incoming, dhcpv6request)},
          (Dhcpv6_wire.buf_of_pkt dhcpv6request))
    | Some DHCP6ADVERTISE, _ -> (* DHCP6ADVERTISE is irrelevant when we're not selecting *)
      `Noop
    | Some DHCPV6REPLY, Requesting _ -> `New_lease ({t with state = Bound incoming}, incoming)
    | Some DHCPV6REPLY, Soliciting _ (* too soon *)
    | Some DHCPV6REPLY, Bound _ -> (* too late *)
      `Noop
    | Some DHCPV6SOLICIT, _ | Some DHCPV6DECLINE, _
    | Some DHCP6REQUEST, _ ->
      (* we don't need to care about these client messages *)
      `Noop
    end else `Noop
