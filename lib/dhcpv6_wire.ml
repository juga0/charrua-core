(*
 * Copyright (c) 2015-2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2016-2017 Mindy Preston
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Sexplib.Conv
open Sexplib.Std

let some_or_invalid f v = match f v with
  | Some x -> x
  | None -> invalid_arg ("Invalid value " ^ (string_of_int v))

[%%cstruct
type dhcp = {
  op:     uint8_t;
  htype:  uint8_t;
  hlen:   uint8_t;
  hops:   uint8_t;
  xid:    uint32_t;
  Elapsed_time:   uint16_t;
  flags:  uint16_t;
  ciaddr: uint32_t;
  yiaddr: uint32_t;
  siaddr: uint32_t;
  giaddr: uint32_t;
  chaddr: uint8_t   [@len 16];
  sname:  uint8_t   [@len 64];
  file:   uint8_t   [@len 128];
} [@@big_endian]
]
[%%cenum
type op =
  | BOOTREQUEST [@id 1]
  | BOOTREPLY   [@id 2]
[@@uint8_t][@@sexp]]

let int_to_op_exn v = some_or_invalid int_to_op v

[%%cenum
type msgtype =
  | DHCP6SOLICIT [@id 1]
  | DHCP6ADVERTISE
  | DHCP6REQUEST
  | DHCP6CONFIRM
  | DHCP6RENEW
  | DHCP6REBIND
  | DHCP6REPLY
  | DHCP6RELEASE
  | DHCP6DECLINE
  | DHCP6RECONFIGURE
  | DHCP6INFORMATIONREQUEST
  | DHCP6RELAYFORW
  | DHCP6RELAYREPL
  | DHCP6MESSAGEMAX
[@@uint8_t][@@sexp]]

let int_to_msgtype_exn v = some_or_invalid int_to_msgtype v

[%%cenum
type option_code =
  | CLIENTID            [@id 1]
  | SERVERID            [@id 2]
  | IA_NA               [@id 3]
  | IA_TA               [@id 4]
  | IAADDR              [@id 5]
  | ORO                 [@id 6]
  | PREFERENCE          [@id 7]
  | ELAPSED_TIME        [@id 8]
  | RELAY_MSG           [@id 9]
  (* option code 10 is unassigned *)
  | AUTH                [@id 11]
  | UNICAST             [@id 12]
  | STATUS_CODE         [@id 13]
  | RAPID_COMMIT        [@id 14]
  | USER_CLASS          [@id 15]
  | VENDOR_CLASS        [@id 16]
  | VENDOR_OPTS         [@id 17]
  | INTERFACE_ID        [@id 18]
  | RECONF_MSG          [@id 19]
  | RECONF_ACCEPT       [@id 20]
  | DNS_SERVERS         [@id 23]  (* RFC 3646 *)
  | DOMAIN_LIST         [@id 24]  (* RFC 3646 *)
  | SNTP_SERVERS        [@id 31]  (* RFC 4075, deprecated *)
  (* option code 35 is unassigned *)
  | NTP_SERVER          [@id 56]  (* RFC 5908 *)
  (* option codes 89-142 are unassigned *)
  (* option codes 144-65535 are unassigned *)
[@@uint8_t][@@sexp]]

let int_to_option_code_exn v = some_or_invalid int_to_option_code v

type htype =
  | Ethernet_10mb
  | Other [@@deriving sexp]

type flags =
  | Broadcast
  | Unicast [@@deriving sexp]

type client_id =
  | Hwaddr of Macaddr.t
  | Id of string [@@deriving sexp]

type dhcp_option =
  [@@deriving sexp]

type pkt = {
  srcmac  : Macaddr.t;
  dstmac  : Macaddr.t;
  srcip   : Ipaddr.V6.t;
  dstip   : Ipaddr.V6.t;
  srcport : int;
  dstport : int;
  op      : op;
  xid     : int32;
  Elapsed_time    : int;
  options : dhcp_option list;
} [@@deriving sexp]

let client_port = 546
let server_port = 547

let options_of_buf buf buf_len =
  let rec collect buf options =
    let code = Cstruct.get_uint8 buf 0 in
    let padding () = collect (Cstruct.shift buf 1) options in
    (* Make sure we never shift into an unexisting body *)
    match int_to_option_code_exn code with
    | _ -> (* Has len:body, generate the get functions *)
      let len = Cstruct.get_uint8 buf 1 in
      let body = Cstruct.shift buf 2 in
      let bad_len = Printf.sprintf "Malformed len %d in option %d" len code in
      (* discard discards the option from the resulting list *)
      let discard () = collect (Cstruct.shift body len) options in
      (* take includes the option in the resulting list *)
      let take op = collect (Cstruct.shift body len) (op :: options) in
      let get_8 () = if len <> 1 then invalid_arg bad_len else
          Cstruct.get_uint8 body 0 in
      let get_8_list ?(min_len=1) () =
        let rec loop offset octets =
          if offset = len then octets else
            let octet = Cstruct.get_uint8 body offset in
            loop (succ offset) (octet :: octets)
        in
        if len < min_len then invalid_arg bad_len else
          List.rev (loop 0 [])
      in
      let get_bool () = match (get_8 ()) with
        | 1 -> true
        | 0 -> false
        | v -> invalid_arg ("invalid value for bool: " ^ string_of_int v)
      in
      let get_16 () = if len <> 2 then invalid_arg bad_len else
          Cstruct.BE.get_uint16 body 0 in
      let get_16_list ?(min_len=2) () =
        let rec loop offset shorts =
          if offset = len then shorts else
            let short = Cstruct.BE.get_uint16 body offset in
            loop (offset + 2) (short :: shorts)
        in
        if ((len mod 2) <> 0) || len < 2 then invalid_arg bad_len else
          List.rev (loop 0 [])
      in
      let get_32 () = if len <> 4 then invalid_arg bad_len else
          Cstruct.BE.get_uint32 body 0 in
      let get_32_list ?(min_len=4) () =
        let rec loop offset longs =
          if offset = len then longs else
            let long = Cstruct.BE.get_uint32 body offset in
            loop (offset + 4) (long :: longs)
        in
        if ((len mod 4) <> 0) || len < min_len then invalid_arg bad_len else
          List.rev (loop 0 [])
      in
      (* Fetch ipv4s from options *)
      let get_ip () = if len <> 4 then invalid_arg bad_len else
          Ipaddr.V6.of_int32 (get_32 ()) in
      let get_ip_list ?(min_len=4) () =
        List.map Ipaddr.V6.of_int32 (get_32_list ~min_len:min_len ())
      in
      let get_ip_tuple_list l =
        let rec loop ips tuples = match ips with
          | ip1 :: ip2 :: tl -> loop tl ((ip1, ip2) :: tuples)
          | ip :: [] -> invalid_arg bad_len
          | [] -> List.rev tuples
        in
        loop (get_ip_list ~min_len:8 ()) []
      in
      (* Get a list of ip pairs *)
      let get_prefix_list ?(min_len=8) () =
        if ((len mod 8) <> 0) || len < min_len then
          invalid_arg bad_len
        else
          List.map (function
              | addr, mask -> try
                  Ipaddr.V6.Prefix.of_netmask mask addr
                with
                  Ipaddr.Parse_error (a, b) -> invalid_arg (a ^ ": " ^ b))
            (get_ip_tuple_list ())
      in
      let get_string () =  if len < 1 then invalid_arg bad_len else
          Cstruct.copy body 0 len
      in
      let get_client_id () =  if len < 2 then invalid_arg bad_len else
          let s = Cstruct.copy body 1 (len - 1) in
          if (Cstruct.get_uint8 body 0) = 1 && len = 7 then
            Hwaddr (Macaddr.of_bytes_exn s)
          else
            Id s
      in
      match code with
      | code -> discard ()
  in
  (* Extends options if it finds an Option_overload *)
  let extend buf options =
    let rec search = function
      | [] -> None
      | opt :: tl -> match opt with
        | Option_overload v -> Some v
        | _ -> search tl
    in
    match search options with
    | None -> options           (* Nothing to do, identity function *)
    | Some v -> match v with
      | _ -> invalid_arg ("Invalid overload code: " ^ string_of_int v)
  in
  (* Handle a pkt with no options *)
  if buf_len = sizeof_dhcp then
    []
  else
    (* Look for magic cookie *)
    let cookie = Cstruct.BE.get_uint32 buf sizeof_dhcp in
    if cookie <> 0x63825363l then
      invalid_arg "Invalid cookie";
    let options_start = Cstruct.shift buf (sizeof_dhcp + 4) in
    (* Jump over cookie and start options, also extend them if necessary *)
    collect options_start [] |>
    extend buf |>
    List.rev

let buf_of_options sbuf options =
  let open Cstruct in
  let put_code code buf = set_uint8 buf 0 code; shift buf 1 in
  let put_len len buf = if len > 255 then
      invalid_arg ("option len is too big: " ^ (string_of_int len));
    set_uint8 buf 0 len; shift buf 1
  in
  let put_8 v buf = set_uint8 buf 0 v; shift buf 1 in
  let put_16 v buf = BE.set_uint16 buf 0 v; shift buf 2 in
  let put_32 v buf = BE.set_uint32 buf 0 v; shift buf 4 in
  let put_ip ip buf = put_32 (Ipaddr.V6.to_int32 ip) buf in
  let put_prefix prefix buf =
    put_ip (Ipaddr.V6.Prefix.network prefix) buf |>
    put_ip (Ipaddr.V6.Prefix.netmask prefix)
  in
  let put_ip_tuple tuple buf = match tuple with
    a, b -> put_ip a buf |> put_ip b
  in
  let put_coded_8 code v buf = put_code code buf |> put_len 1 |> put_8 v in
  let put_coded_16 code v buf = put_code code buf |> put_len 2 |> put_16 v in
  let put_coded_32 code v buf = put_code code buf |> put_len 4 |> put_32 v in
  let put_coded_ip code ip buf = put_code code buf |> put_len 4 |> put_ip ip in
  (* let put_coded_prefix code prefix buf = *)
  (*   put_code code buf |> put_len 8 |> put_prefix prefix in *)
  let put_coded_bool code v buf =
    put_coded_8 code (match v with true -> 1 | false -> 0) buf in
  let put_coded_bytes code v buf =
    let len = (String.length v) in
    let buf = put_code code buf |> put_len len in
    blit_from_string v 0 buf 0 len;
    shift buf len
  in
  let put_client_id code v buf =
    let htype, s = match v with
      | Hwaddr mac -> (1, Macaddr.to_bytes mac)
      | Id id -> (0, id)
    in
    let len = String.length s in
    let buf = put_code code buf |> put_len (succ len) |> put_8 htype in
    blit_from_string s 0 buf 0 len;
    shift buf len
  in
  let make_listf ?(min_len=1) f len code l buf =
    if (List.length l) < min_len then invalid_arg "Invalid option" else
    let buf = put_code code buf |> put_len (len * (List.length l)) in
    List.fold_left f buf l
  in
  let put_coded_8_list ?min_len =
    make_listf ?min_len (fun buf x -> put_8 x buf) 1 in
  let put_coded_16_list ?min_len =
    make_listf ?min_len (fun buf x -> put_16 x buf) 2 in
  (* let put_coded_32_list = make_listf (fun buf x -> put_32 x buf) 4 in *)
  let put_coded_ip_list ?min_len =
    make_listf ?min_len (fun buf x -> put_ip x buf) 4 in
  let put_coded_prefix_list ?min_len =
    make_listf ?min_len (fun buf x -> put_prefix x buf) 8 in
  let put_coded_ip_tuple_list ?min_len =
    make_listf ?min_len (fun buf x -> put_ip_tuple x buf) 8 in
  let buf_of_option buf option =
    match option with
  in
  match options with
  | [] -> invalid_arg "Invalid options"
  | _ ->
    let () = BE.set_uint32 sbuf 0 0x63825363l in       (* put cookie *)
    let sbuf = shift sbuf 4 in
    let ebuf = List.fold_left buf_of_option sbuf options in
    set_uint8 ebuf 0 (option_code_to_int END); shift ebuf 1

let pkt_of_buf buf len =
  let open Rresult in
  let open Printf in
  let wrap () =
    let min_len = sizeof_dhcp + Ethif_wire.sizeof_ethernet +
                  Ipv6_wire.sizeof_ipv4 + Udp_wire.sizeof_udp
    in
    Util.guard (len >= min_len)
      (sprintf "packet is too small: %d < %d" len min_len)
    >>= fun () ->
    (* Handle ethernet *)
    Ethif_packet.Unmarshal.of_cstruct buf >>= fun (eth_header, eth_payload) ->
    match eth_header.Ethif_packet.ethertype with
    | Ethif_wire.ARP | Ethif_wire.IPv6 -> Error "packet is not ipv4"
    | Ethif_wire.IPv6 ->
      Ipv6_packet.Unmarshal.of_cstruct eth_payload
      >>= fun (ipv4_header, ipv4_payload) ->
      match Ipv6_packet.Unmarshal.int_to_protocol ipv4_header.Ipv6_packet.proto with
      | Some `ICMP | Some `TCP | None -> Error "packet is not udp"
      | Some `UDP ->
        Util.guard
          (Ipv6_packet.Unmarshal.verify_transport_checksum
             ~proto:`UDP ~ipv4_header ~transport_packet:ipv4_payload)
          "bad udp checksum"
        >>= fun () ->
        Udp_packet.Unmarshal.of_cstruct ipv4_payload >>=
        fun (udp_header, udp_payload) ->
        let op = int_to_op_exn (get_dhcp_op udp_payload) in
        let xid = get_dhcp_xid udp_payload in
        let Elapsed_time = get_dhcp_elapsed_time udp_payload in
        let options = options_of_buf udp_payload len in
        Ok { srcmac = eth_header.Ethif_packet.source;
                    dstmac = eth_header.Ethif_packet.destination;
                    srcip = ipv4_header.Ipv6_packet.src;
                    dstip = ipv4_header.Ipv6_packet.dst;
                    srcport = udp_header.Udp_packet.src_port;
                    dstport = udp_header.Udp_packet.dst_port;
                    op; xid; Elapsed_time; options }
  in
  try wrap () with | Invalid_argument e -> Error e

let buf_of_pkt pkt =
  let dhcp = Cstruct.create 2048 in
  set_dhcp_op dhcp (op_to_int pkt.op);
  set_dhcp_xid dhcp pkt.xid;
  set_dhcp_elapsed_time dhcp pkt.Elapsed_time;
  let options_start = Cstruct.shift dhcp sizeof_dhcp in
  let options_end = buf_of_options options_start pkt.options in
  let partial_len = (Cstruct.len dhcp) - (Cstruct.len options_end) in
  let buf_end =
    if 300 - partial_len > 0 then
      let pad_len = 300 - partial_len in
      let () =
        for i = 0 to pad_len do
          Cstruct.set_uint8 options_end i 0
        done
      in
      Cstruct.shift options_end pad_len
    else
      options_end
  in
  let dhcp = Cstruct.set_len dhcp ((Cstruct.len dhcp) - (Cstruct.len buf_end)) in
  (* Ethernet *)
  let ethernet = Ethif_packet.(Marshal.make_cstruct
                                 { source = pkt.srcmac;
                                   destination = pkt.dstmac;
                                   ethertype = Ethif_wire.IPv6; })
  in
  (* IPv6 *)
  let pseudoheader = Ipv6_packet.Marshal.pseudoheader
      ~src:pkt.srcip ~dst:pkt.dstip ~proto:`UDP
      (Udp_wire.sizeof_udp + Cstruct.len dhcp)
  in
  (* UDP *)
  let udp = Udp_packet.(Marshal.make_cstruct ~pseudoheader ~payload:dhcp
                          { src_port = pkt.srcport;
                            dst_port = pkt.dstport })
  in
  let ip = Ipv6_packet.(Marshal.make_cstruct ~payload_len:(Cstruct.lenv [udp;dhcp])
                          { src = pkt.srcip; dst = pkt.dstip;
                            proto = (Marshal.protocol_to_int `UDP);
                            ttl = 255;
                            options = Cstruct.create 0; })
  in
  Cstruct.concat [ ethernet; ip; udp; dhcp ]

let is_dhcp buf len =
  let open Rresult in
  let aux buf =
    Ethif_packet.Unmarshal.of_cstruct buf >>= fun (eth_header, eth_payload) ->
    match eth_header.Ethif_packet.ethertype with
    | Ethif_wire.ARP | Ethif_wire.IPv6 -> Ok false
    | Ethif_wire.IPv6 ->
      Ipv6_packet.Unmarshal.of_cstruct eth_payload >>= fun (ipv4_header, ipv4_payload) ->
      (* TODO: tcpip doesn't currently do checksum checking, so we lose some
         functionality by making this change *)
      match Ipv6_packet.Unmarshal.int_to_protocol ipv4_header.Ipv6_packet.proto with
      | Some `ICMP | Some `TCP | None -> Ok false
      | Some `UDP ->
        Udp_packet.Unmarshal.of_cstruct ipv4_payload >>=
        fun (udp_header, udp_payload) ->
        Ok ((udp_header.Udp_packet.dst_port = server_port ||
             udp_header.Udp_packet.dst_port = client_port)
            &&
            (udp_header.Udp_packet.src_port = server_port ||
             udp_header.Udp_packet.src_port = client_port))
  in
  match aux buf with
  | Ok b -> b
  | Error _ -> false

let find_option f options = Util.find_map f options

let collect_options f options = Util.filter_map f options |> List.flatten

let client_id_of_pkt pkt =
  match find_option
          (function Client_id id -> Some id | _ -> None)
          pkt.options
  with
  | Some id -> id
  | None -> Hwaddr pkt.chaddr

(* string_of_* functions *)
let to_hum f x = Sexplib.Sexp.to_string_hum (f x)
let client_id_to_string = to_hum sexp_of_client_id
let pkt_to_string = to_hum sexp_of_pkt
let dhcp_option_to_string = to_hum sexp_of_dhcp_option

let collect_ntp_servers =
  collect_options (function Ntp_servers x -> Some x | _ -> None)
