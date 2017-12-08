(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

(** {1 DHCP wire parsers} *)

(** {2 DHCP general data} *)

val client_port : int
(** DHCP client port [546] *)

val server_port : int
(** DHCP server port [547] *)

(** {2 DHCP header opcodes} *)

type op =
  | BOOTREQUEST
  | BOOTREPLY

(** Conversions of {! op}s. *)

val int_to_op : int -> op option
val int_to_op_exn : int -> op
(** @raise Invalid_argument if [v < 0 || v > 255]  *)
val op_to_int : op -> int

val string_to_op : string -> op option
val op_to_string : op -> string

val sexp_of_op : op -> Sexplib.Sexp.t
val op_of_sexp : Sexplib.Sexp.t -> op

(** {2 DHCP message type option values} *)

type msgtype =
  | DHCP6SOLICIT
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
(** Conversions of {! msgtype}s. *)

val msgtype_to_int : msgtype -> int
val int_to_msgtype : int -> msgtype option
val int_to_msgtype_exn : int -> msgtype
(** @raise Invalid_argument if not a valid {! msgtype} value *)

val string_to_msgtype : string -> msgtype option
val msgtype_to_string : msgtype -> string

val sexp_of_msgtype : msgtype -> Sexplib.Sexp.t
val msgtype_of_sexp : Sexplib.Sexp.t -> msgtype

(** {2 DHCP option codes (names only, for use in parameter requests)} *)

type option_code =
  | CLIENTID
  | SERVERID
  | IA_NA
  | IA_TA
  | IAADDR
  | ORO
  | PREFERENCE
  | ELAPSED_TIME
  | RELAY_MSG
  (* option code 10 is unassigned *)
  | AUTH
  | UNICAST
  | STATUS_CODE
  | RAPID_COMMIT
  | USER_CLASS
  | VENDOR_CLASS
  | VENDOR_OPTS
  | INTERFACE_ID
  | RECONF_MSG
  | RECONF_ACCEPT
  | DNS_SERVERS (* RFC 3646 *)
  | DOMAIN_LIST (* RFC 3646 *)
  | SNTP_SERVERS31  (* RFC 4075, deprecated *)
  (* option code 35 is unassigned *)
  | NTP_SERVER (* RFC 5908 *)
(* option codes 89-142 are unassigned *)
(* option codes 144-65535 are unassigned *)

(** The type of a dhcp parameter request, these are all the values according to
    {{:https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml}iana}
*)

(** Conversions of DHCP {! option_code}s. *)

val int_to_option_code : int -> option_code option
val int_to_option_code_exn : int -> option_code
val option_code_to_int : option_code -> int

val sexp_of_option_code : option_code -> Sexplib.Sexp.t
val option_code_of_sexp : Sexplib.Sexp.t -> option_code

val string_to_option_code : string -> option_code option
val option_code_to_string : option_code -> string


(** {2 DHCP Client identifier}. *)

type client_id =
  | Hwaddr of Macaddr.t
  | Id of string
(** A client_id is usually a mac address from a {! dhcp_option},
    but it can also be an opaque string. See {! client_id_of_pkt}. *)

(** Conversions of {! client_id}. *)

val client_id_of_sexp : Sexplib.Sexp.t -> client_id
val sexp_of_client_id : client_id -> Sexplib.Sexp.t

val client_id_to_string : client_id -> string

(** {2 DHCP options} *)

type dhcp_option =
  [@@deriving sexp]
(** Not all options are currently implemented. *)

(** Conversions of {! dhcp_option}. *)

val buf_of_options : Cstruct.t -> dhcp_option list -> Cstruct.t
val options_of_buf : Cstruct.t -> int -> dhcp_option list

val find_option : (dhcp_option -> 'b option) -> dhcp_option list -> 'b option
(** [find_option f l] finds the first option where [f] evaluates to [Some] value
    on list [l] *)

val collect_options : ('a -> 'b list option) -> 'a list -> 'b list
(** [collect_options f l] collects all options where [f] evaluates to [Some]
    value on list [l], this is useful for list options like [Routers], if
    multiple list options are found, the resulting list is flattened. *)

val dhcp_option_of_sexp : Sexplib.Sexp.t -> dhcp_option
val sexp_of_dhcp_option : dhcp_option -> Sexplib.Sexp.t

val dhcp_option_to_string : dhcp_option -> string

val collect_ntp_servers : dhcp_option list -> Ipaddr.V6.t list

(** {2 DHCP Packet - fixed-length fields, plus a variable-length list of options} *)

type pkt = {
  srcmac : Macaddr.t;
  dstmac : Macaddr.t;
  srcip : Ipaddr.V6.t;
  dstip : Ipaddr.V6.t;
  srcport : int;
  dstport : int;
  op : op;
  xid : int32;
  Elapsed_time : int;
  options : dhcp_option list;
}

(** Conversions for {! pkt}. *)

val pkt_of_buf : Cstruct.t -> int -> (pkt, string) result
val buf_of_pkt : pkt -> Cstruct.t

val pkt_of_sexp : Sexplib.Sexp.t -> pkt
val sexp_of_pkt : pkt -> Sexplib.Sexp.t

val client_id_of_pkt : pkt -> client_id
val pkt_to_string : pkt -> string

(** Helpers. *)

val is_dhcp : Cstruct.t -> int -> bool
(** [is_dhcp buf len] is true if [buf] is an Ethernet frame containing an IPv6
    header, UDP header, and DHCP packet. *)
