// Draft implementation attempt at ABNF cming from IETF's RFC 3986.
// (https://www.ietf.org/rfc/rfc3986.txt)

// intent is to parse the inpt string for URI only, no AST/extra processing needed...

// TODO - one_of() vs alt() for various chars? (consume 1 vs greedy more???)

use nom::{
    branch::alt,
    bytes::complete::{tag},
    character::{
        complete::{anychar, char, one_of},
        is_alphabetic, is_digit,
    },
    combinator::{not, opt, recognize, verify},
    multi::{count, many0, many1, many_m_n},
    sequence::{pair, tuple},
    IResult,
};

//    URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
pub fn uri(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        scheme,
        recognize(char(':')),
        hier_part,
        opt(pair(char('?'), query)),
        opt(pair(char('#'), fragment)),
    )))(input)
}

//    hier-part     = "//" authority path-abempty
//                  / path-absolute
//                  / path-rootless
//                  / path-empty
fn hier_part(input: &str) -> IResult<&str, &str> {
    alt((
        recognize(tuple((tag("//"), authority, path_abempty))),
        path_absolute,
        path_rootless,
        path_empty,
    ))(input)
}

//    URI-reference = URI / relative-ref
pub fn uri_reference(input: &str) -> IResult<&str, &str> {
    alt((uri, relative_ref))(input)
}

//    absolute-URI  = scheme ":" hier-part [ "?" query ]
pub fn absolute_uri(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        scheme,
        char(':'),
        hier_part,
        opt(pair(char('?'), query)),
    )))(input)
}

//    relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
fn relative_ref(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        relative_part,
        opt(pair(char('?'), query)),
        opt(pair(char('#'), fragment)),
    )))(input)
}

//    relative-part = "//" authority path-abempty
//                  / path-absolute
//                  / path-noscheme
//                  / path-empty
fn relative_part(input: &str) -> IResult<&str, &str> {
    recognize(alt((
        recognize(tuple((tag("//"), authority, path_abempty))),
        path_absolute,
        path_noscheme,
        path_empty,
    )))(input)
}

//    scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
fn scheme(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alpha,
        many0(alt((alpha, digit, recognize(one_of("+-."))))),
    ))(input)
}

//    authority     = [ userinfo "@" ] host [ ":" port ]
pub fn authority(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        opt(pair(userinfo, char('@'))),
        tag("host"),
        opt(pair(char(':'), port)),
    )))(input)
}

//    userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
pub fn userinfo(input: &str) -> IResult<&str, &str> {
    recognize(many0(alt((
        unreserved,
        pct_encoded,
        sub_delims,
        recognize(char(':')),
    ))))(input)
}

//    host          = IP-literal / IPv4address / reg-name
pub fn host(input: &str) -> IResult<&str, &str> {
    alt((ip_literal, ipv4address, reg_name))(input)
}

//    port          = *DIGIT
pub fn port(input: &str) -> IResult<&str, &str> {
    recognize(many0(digit))(input)
}

//    IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
fn ip_literal(input: &str) -> IResult<&str, &str> {
    recognize(tuple((tag("["), alt((ipv6address, ipvfuture)), tag("]"))))(input)
}

//    IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
fn ipvfuture(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        char('v'),
        many1(hexdig),
        char('.'),
        many1(alt((unreserved, sub_delims, recognize(char(':'))))),
    )))(input)
}

//    IPv6address   =                            6( h16 ":" ) ls32
//                  /                       "::" 5( h16 ":" ) ls32
//                  / [               h16 ] "::" 4( h16 ":" ) ls32
//                  / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//                  / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//                  / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
//                  / [ *4( h16 ":" ) h16 ] "::"              ls32
//                  / [ *5( h16 ":" ) h16 ] "::"              h16
//                  / [ *6( h16 ":" ) h16 ] "::"
fn ipv6address(input: &str) -> IResult<&str, &str> {
    let v1 = tuple((count(pair(h16, char(':')), 6), ls32));
    let v2 = tuple((tag("::"), count(pair(h16, char(':')), 5), ls32));
    let v3 = tuple((opt(h16), tag("::"), count(pair(h16, char(':')), 4), ls32));
    let v4 = tuple((
        opt(pair(many_m_n(0, 1, pair(h16, char(':'))), h16)),
        tag("::"),
        count(pair(h16, char(':')), 3),
        ls32,
    ));
    let v5 = tuple((
        opt(pair(many_m_n(0, 2, pair(h16, char(':'))), h16)),
        tag("::"),
        count(pair(h16, char(':')), 2),
        ls32,
    ));
    let v6 = tuple((
        opt(pair(many_m_n(0, 3, pair(h16, char(':'))), h16)),
        tag("::"),
        h16,
        char(':'),
        ls32,
    ));
    let v7 = tuple((
        opt(pair(many_m_n(0, 4, pair(h16, char(':'))), h16)),
        tag("::"),
        ls32,
    ));
    let v8 = tuple((
        opt(pair(many_m_n(0, 5, pair(h16, char(':'))), h16)),
        tag("::"),
        h16,
    ));
    let v9 = tuple((
        opt(pair(many_m_n(0, 6, pair(h16, char(':'))), h16)),
        tag("::"),
    ));
    recognize(alt((
        recognize(v1),
        recognize(v2),
        recognize(v3),
        recognize(v4),
        recognize(v5),
        recognize(v6),
        recognize(v7),
        recognize(v8),
        recognize(v9),
    )))(input)
}

//    h16           = 1*4HEXDIG
fn h16(input: &str) -> IResult<&str, &str> {
    recognize(many_m_n(1, 4, hexdig))(input)
}

//    ls32          = ( h16 ":" h16 ) / IPv4address
fn ls32(input: &str) -> IResult<&str, &str> {
    alt((recognize(tuple((h16, char(':'), h16))), ipv4address))(input)
}

//    IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
fn ipv4address(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        dec_octet,
        char('.'),
        dec_octet,
        char('.'),
        dec_octet,
        char('.'),
        dec_octet,
    )))(input)
}

//    dec-octet     = DIGIT                 ; 0-9
//                  / %x31-39 DIGIT         ; 10-99
//                  / "1" 2DIGIT            ; 100-199
//                  / "2" %x30-34 DIGIT     ; 200-249
//                  / "25" %x30-35          ; 250-255
fn dec_octet(input: &str) -> IResult<&str, &str> {
    alt((
        digit,
        recognize(pair(recognize(one_of("123456789")), digit)),
        recognize(pair(recognize(char('1')), count(digit, 2))),
        recognize(tuple((char('2'), one_of("01234"), digit))),
        recognize(pair(tag("25"), one_of("012345"))),
    ))(input)
}

//    reg-name      = *( unreserved / pct-encoded / sub-delims )
fn reg_name(input: &str) -> IResult<&str, &str> {
    recognize(many0(alt((unreserved, pct_encoded, sub_delims))))(input)
}

//    path          = path-abempty    ; begins with "/" or is empty
//                  / path-absolute   ; begins with "/" but not "//"
//                  / path-noscheme   ; begins with a non-colon segment
//                  / path-rootless   ; begins with a segment
//                  / path-empty      ; zero characters
fn path(input: &str) -> IResult<&str, &str> {
    alt((
        path_abempty,
        path_absolute,
        path_noscheme,
        path_rootless,
        path_empty,
    ))(input)
}

//    path-abempty  = *( "/" segment )
pub fn path_abempty(input: &str) -> IResult<&str, &str> {
    recognize(many0(pair(char('/'), segment)))(input)
}

//    path-absolute = "/" [ segment-nz *( "/" segment ) ]
pub fn path_absolute(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        recognize(char('/')),
        recognize(opt(pair(
            segment_nz,
            recognize(many0(pair(recognize(char('/')), segment))),
        ))),
    ))(input)
}

//    path-noscheme = segment-nz-nc *( "/" segment )
fn path_noscheme(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        segment_nz_nc,
        recognize(many0(pair(char('/'), segment))),
    ))(input)
}

//    path-rootless = segment-nz *( "/" segment )
fn path_rootless(input: &str) -> IResult<&str, &str> {
    recognize(pair(segment_nz, recognize(many0(pair(char('/'), segment)))))(input)
}

//    path-empty    = 0<pchar>
fn path_empty(input: &str) -> IResult<&str, &str> {
    recognize(not(pchar))(input)
}

//    segment       = *pchar
fn segment(input: &str) -> IResult<&str, &str> {
    recognize(many0(pchar))(input)
}

//    segment-nz    = 1*pchar
fn segment_nz(input: &str) -> IResult<&str, &str> {
    recognize(many1(pchar))(input)
}

//    segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//                  ; non-zero-length segment without any colon ":"
fn segment_nz_nc(input: &str) -> IResult<&str, &str> {
    recognize(many1(alt((
        unreserved,
        pct_encoded,
        sub_delims,
        recognize(char('@')),
    ))))(input)
}

//    pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
fn pchar(input: &str) -> IResult<&str, &str> {
    alt((
        unreserved,
        pct_encoded,
        sub_delims,
        recognize(char(':')),
        recognize(char('@')),
    ))(input)
}

//    query         = *( pchar / "/" / "?" )
fn query(input: &str) -> IResult<&str, &str> {
    recognize(many0(alt((
        pchar,
        recognize(char('/')),
        recognize(char('?')),
    ))))(input)
}

//    fragment      = *( pchar / "/" / "?" )
fn fragment(input: &str) -> IResult<&str, &str> {
    recognize(many0(alt((
        pchar,
        recognize(char('/')),
        recognize(char('?')),
    ))))(input)
}

//    pct-encoded   = "%" HEXDIG HEXDIG
fn pct_encoded(input: &str) -> IResult<&str, &str> {
    recognize(tuple((char('%'), hexdig, hexdig)))(input)
}

// HEXDIG from ABNF RFC 2234
fn hexdig(input: &str) -> IResult<&str, &str> {
    // HEXDIG         =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
    alt((digit, recognize(one_of("ABCDEF"))))(input)
}

//    unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
fn unreserved(input: &str) -> IResult<&str, &str> {
    alt((alpha, digit, recognize(one_of("-._~"))))(input)
}

// ALPHA from ABNF RFC 2234
fn alpha(input: &str) -> IResult<&str, &str> {
    // ALPHA          =  %x41-5A / %x61-7A
    // let r = (0x41..=0x5A).map(char::from).collect::<Vec<_>>();
    // let s = String::from_iter(r);
    recognize(verify(anychar, |c| is_alphabetic(*c as u8)))(input)
}

// DIGIT from ABNF RFC 2234
fn digit(input: &str) -> IResult<&str, &str> {
    // DIGIT = %x30-39
    // let r = (0x30..=0x39).map(char::from).collect::<Vec<_>>();
    // let s = String::from_iter(r);
    // recognize(one_of(s.as_str()))(input)
    recognize(verify(anychar, |c| is_digit(*c as u8)))(input)
}

//    reserved      = gen-delims / sub-delims
fn reserved(input: &str) -> IResult<&str, &str> {
    alt((gen_delims, sub_delims))(input)
}

//    gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
fn gen_delims(input: &str) -> IResult<&str, &str> {
    recognize(one_of(":/?#[]@"))(input)
}

//    sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//                  / "*" / "+" / "," / ";" / "="
fn sub_delims(input: &str) -> IResult<&str, &str> {
    recognize(one_of("!$&'()*+,;="))(input)
}
