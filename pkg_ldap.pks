create or replace package pkg_ldap as
  -- Types
  subtype ldap_attribute is varchar2(256);
  type r_value is record (
    type   varchar2(1),
    length pls_integer,
    text   varchar2(32767),
    bin    blob
  );
  type t_values          is table of r_value;
  type t_attributes      is table of t_values index by ldap_attribute;
  type t_attributes_list is table of ldap_attribute;
  type r_entries is record (
    name            ldap_attribute,
    attributes      t_attributes,
    attributes_list t_attributes_list
  );
  type t_entries is table of r_entries;
  type t_users   is table of ldap_attribute;

  -- Constants
  c_debug         constant boolean        := true;
  c_attr_username constant ldap_attribute := 'sAMAccountName';
  c_attr_dn       constant ldap_attribute := 'distinguishedName';

  -- Connection
  procedure set_credentials(p_host        in varchar2,
                            p_port        in number,
                            p_username    in varchar2,
                            p_password    in varchar2,
                            p_ldap_base   in varchar2,
                            p_wallet_path in varchar2    default null,
                            p_wallet_pass in varchar2    default null,
                            p_wallet_mode in pls_integer default 2);
  procedure connect_ldap;
  procedure disconnect_ldap;
  function is_connected return boolean;

  -- Features - Call only when already connected
  function check_login(p_username in varchar2,
                       p_password in varchar2) return boolean;
  procedure get_user_attributes(p_username         in varchar2,
                                p_attrib           in varchar2 default null,
                                p_attributes      out t_attributes,
                                p_attributes_list out t_attributes_list);
  function get_user_attribute(p_username in varchar2, p_attribute in varchar2) return varchar2;
  function get_user_attribute_bin(p_username in varchar2, p_attribute in varchar2) return blob;
  function get_users_by_attr(p_search_attr   in varchar2,
                             p_search_value  in varchar2,
                             p_username_attr in varchar2 default c_attr_username) return t_users;
  function get_users_by_dn(p_dn            in varchar2,
                           p_username_attr in varchar2 default c_attr_username) return t_users;

  -- Utils
  function ldap_timestamp2date(p_ldap_timestamp in varchar2) return date;
  function filetime2date(p_filetime in number) return date;
end pkg_ldap;
/