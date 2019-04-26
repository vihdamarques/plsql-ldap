create or replace package body pkg_ldap as
  -- Credentials
  g_host        varchar2(255);
  g_port        pls_integer;
  g_username    varchar2(255);
  g_password    varchar2(255);
  g_ldap_base   varchar2(4000);
  g_wallet_path varchar2(255);
  g_wallet_pass varchar2(255);
  g_wallet_mode pls_integer;

  -- Common Use
  g_session dbms_ldap.session;
  g_retval  pls_integer;

  procedure set_credentials(p_host        in varchar2,
                            p_port        in number,
                            p_username    in varchar2,
                            p_password    in varchar2,
                            p_ldap_base   in varchar2,
                            p_wallet_path in varchar2    default null,
                            p_wallet_pass in varchar2    default null,
                            p_wallet_mode in pls_integer default 2) is
  begin
    if is_connected then -- disconnect if connected
      disconnect_ldap;
    end if;

    g_host        := p_host;
    g_port        := p_port;
    g_username    := p_username;
    g_password    := p_password;
    g_ldap_base   := p_ldap_base;
    g_wallet_path := p_wallet_path;
    g_wallet_pass := p_wallet_pass;
    g_wallet_mode := p_wallet_mode;
  end set_credentials;

  procedure log(p_msg in varchar2) is
  begin
    if c_debug then
      dbms_output.put_line(p_msg);
    end if;
  end log;

  function is_connected return boolean is
  begin
    if g_session is null then
      return false;
    else
      g_retval := dbms_ldap.simple_bind_s(ld     => g_session,
                                          dn     => g_username,
                                          passwd => g_password);

      if g_retval = dbms_ldap.SUCCESS then
        return true;
      else
        return false;
      end if;
    end if;
  exception when others then
    return false;
  end is_connected;

  procedure disconnect_ldap is
  begin
    g_retval := dbms_ldap.unbind_s(ld => g_session);
  exception when others then null;
  end disconnect_ldap;

  procedure connect_ldap is
  begin
    -- Já conectado
    if is_connected then
      return;
    end if;

    if g_username is null or g_password is null then
      raise_application_error(-20001, dbms_ldap.err2string(dbms_ldap.INVALID_CREDENTIALS));
    end if;

    if g_session is not null then
    g_retval := dbms_ldap.simple_bind_s(ld     => g_session,
                                        dn     => g_username,
                                        passwd => g_password);
    end if;

    --disconnect_ldap;
    dbms_ldap.use_exception := true;

    -- Connect
    log('Connecting server ' || g_host || ':' || g_port || ' ...');
    begin
    g_session := dbms_ldap.init(hostname  => g_host,
                                portnum   => g_port);
    exception when others then
      log(dbms_utility.format_error_stack || dbms_utility.format_error_backtrace);
      raise dbms_ldap.init_failed;
    end;
    log('Connected!');

    -- Connect SSL
    if g_wallet_path is not null then
      log('Establishing SSL Connection ...');
      g_retval := dbms_ldap.open_ssl (
                    ld              => g_session,
                    sslwrl          => g_wallet_path,
                    sslwalletpasswd => g_wallet_pass,
                    sslauth         => g_wallet_mode
                  );
      log('SSL Established!');
    end if;

    -- Authenticate
    log('Authenticating ' || g_username || ' ...');
    g_retval := dbms_ldap.simple_bind_s(ld     => g_session,
                                        dn     => g_username,
                                        passwd => g_password);
    log('Authenticated!');    
  exception when others then
    log(dbms_utility.format_error_stack || dbms_utility.format_error_backtrace);
    disconnect_ldap;
    raise;
  end connect_ldap;

  function ldap_timestamp2date(p_ldap_timestamp in varchar2) return date is
    l_date date;
  begin
    l_date := cast (
                to_timestamp_tz (
                  p_ldap_timestamp,
                  'yyyymmddhh24miss.ff3tzr'
                ) at time zone sessiontimezone as date
              );
    return l_date;
  end ldap_timestamp2date;

  function filetime2date(p_filetime in number) return date is
    c_max_filetime_oracle constant number := 2650467743995000000; -- 31/12/9999 21:59:59
    c_max_filetime_ad     constant number := 9223372036854775807;
    c_min_date            constant date := to_date('01/01/1601', 'dd/mm/yyyy');
    l_date                date;
  begin
    l_date := case when p_filetime = 0 or p_filetime > c_max_filetime_oracle then
                null
              else
                cast (
                  from_tz (
                    cast (
                      c_min_date + (p_filetime / 24 / 60 / 60 / power(10, 7)) as timestamp
                    ), 'GMT'
                  ) at time zone sessiontimezone
                  as date
                )
              end;
    return l_date;
  end filetime2date;

  function new_value(p_text in varchar2, p_bin in blob) return r_value is
    l_value r_value;
  begin
    l_value.text := p_text;
    l_value.bin  := p_bin;
    l_value.type := case when p_text is not null then 'T'
                         when p_bin  is not null then 'B'
                         else null
                    end;
    l_value.length := case l_value.type
                        when 'T' then length(l_value.text)
                        when 'B' then dbms_lob.getlength(l_value.bin)
                      end;
    return l_value;
  end new_value;

  procedure retrieve_attributes(p_entry            in dbms_ldap.message,
                                p_attributes      out t_attributes,
                                p_attributes_list out t_attributes_list) is
    l_ber_element     dbms_ldap.ber_element;
    l_attr_name       ldap_attribute;
    l_vals            dbms_ldap.string_collection;
    l_vals_bin        dbms_ldap.blob_collection;
    l_values          t_values := t_values();
    --
    character_set_not_supported exception;
    pragma exception_init(character_set_not_supported, -12703);
  begin
    p_attributes_list := t_attributes_list();
    l_attr_name := dbms_ldap.first_attribute(ld        => g_session,
                                             ldapentry => p_entry,
                                             ber_elem  => l_ber_element);
    << attributes_loop >>
    while l_attr_name is not null loop
      p_attributes_list.extend();
      p_attributes_list(p_attributes_list.count) := l_attr_name;
      l_values.delete;
      -- Try to get string value
      begin
        l_vals := dbms_ldap.get_values(ld        => g_session,
                                       ldapentry => p_entry,
                                       attr      => l_attr_name);
        if l_vals.count > 0 then
          << values_loop >>
          for i in l_vals.first .. l_vals.last loop
            l_values.extend();
            l_values(l_values.count) := new_value(l_vals(i), null);
          end loop values_loop;
        end if;
      exception
      when character_set_not_supported then -- Try to get binary value
        l_vals_bin := dbms_ldap.get_values_blob(ld         => g_session,
                                                 ldapentry => p_entry,
                                                 attr      => l_attr_name);
        if l_vals_bin.count > 0 then
          for i in l_vals_bin.first .. l_vals_bin.last loop
            l_values.extend();
            l_values(l_values.count) := new_value(null, l_vals_bin(i));
          end loop;
        end if;
      when others then
        raise;
      end;

      p_attributes(l_attr_name) := l_values;
      l_attr_name := dbms_ldap.next_attribute(ld        => g_session,
                                              ldapentry => p_entry,
                                              ber_elem  => l_ber_element);
    end loop attributes_loop;
  end retrieve_attributes;

  procedure retrieve_entries(p_message in dbms_ldap.message, p_entries out t_entries) is
    l_entry           dbms_ldap.message;
    l_attributes      t_attributes;
    l_attributes_list t_attributes_list := t_attributes_list();
  begin
    p_entries := t_entries();
    if dbms_ldap.count_entries(ld => g_session, msg => p_message) > 0 then
      l_entry := dbms_ldap.first_entry(ld  => g_session,
                                       msg => p_message);
      << entry_loop >>
      while l_entry is not null loop
        retrieve_attributes(p_entry           => l_entry,
                            p_attributes      => l_attributes,
                            p_attributes_list => l_attributes_list);
        p_entries.extend;
        p_entries(p_entries.count).attributes      := l_attributes;
        p_entries(p_entries.count).attributes_list := l_attributes_list;

        l_entry := dbms_ldap.next_entry(ld  => g_session,
                                        msg => l_entry);
      end loop entry_loop;
    end if;
  --exception when others then
  --  log(dbms_utility.format_error_stack || dbms_utility.format_error_backtrace);
  --  raise;
  end retrieve_entries;

  procedure get_user_attributes(p_username         in varchar2,
                                p_attrib           in varchar2 default null,
                                p_attributes      out t_attributes,
                                p_attributes_list out t_attributes_list) is
    l_attrs   dbms_ldap.string_collection;
    l_message dbms_ldap.message;
    l_entries t_entries;
  begin
    dbms_ldap.utf8_conversion := true;
    l_attrs(1) := nvl(p_attrib, '*');
    g_retval := dbms_ldap.search_s (
                  ld       => g_session,
                  base     => g_ldap_base,
                  scope    => dbms_ldap.scope_subtree,
                  filter   => '(&(objectClass=*)(sAMAccountName=' || p_username || '))',
                  attrs    => l_attrs,
                  attronly => 0,
                  res      => l_message);

    retrieve_entries(l_message, l_entries);
    if l_entries.exists(1) then
      p_attributes      := l_entries(1).attributes;
      p_attributes_list := l_entries(1).attributes_list;
    else
      p_attributes_list := t_attributes_list();
    end if;
  end get_user_attributes;

  function get_user_attribute(p_username in varchar2, p_attribute in varchar2) return varchar2 is
    l_attr      pkg_ldap.t_attributes;
    l_attr_list pkg_ldap.t_attributes_list;
    l_attr_val  pkg_ldap.ldap_attribute;
  begin
    get_user_attributes(p_username        => p_username,
                        p_attrib          => p_attribute,
                        p_attributes      => l_attr,
                        p_attributes_list => l_attr_list);

    for i in 1 .. l_attr(p_attribute).count loop
      l_attr_val := l_attr(p_attribute)(i).text;
      exit;
    end loop;

    return l_attr_val;
  end get_user_attribute;

  function get_user_attribute_bin(p_username in varchar2, p_attribute in varchar2) return blob is
    l_attr      pkg_ldap.t_attributes;
    l_attr_list pkg_ldap.t_attributes_list;
    l_attr_val  blob;
  begin
    get_user_attributes(p_username        => p_username,
                        p_attrib          => p_attribute,
                        p_attributes      => l_attr,
                        p_attributes_list => l_attr_list);

    for i in 1 .. l_attr(p_attribute).count loop
      l_attr_val := l_attr(p_attribute)(i).bin;
      exit;
    end loop;

    return l_attr_val;
  end get_user_attribute_bin;

  function get_users_by_attr(p_search_attr   in varchar2,
                             p_search_value  in varchar2,
                             p_username_attr in varchar2 default c_attr_username) return t_users is
    l_attrs   dbms_ldap.string_collection;
    l_message dbms_ldap.message;
    l_entries t_entries;
    l_users   t_users := t_users();
  begin
    l_attrs(1) := p_username_attr;
    g_retval := dbms_ldap.search_s (
                  ld       => g_session,
                  base     => g_ldap_base,
                  scope    => dbms_ldap.scope_subtree,
                  filter   => '(&(objectClass=*)(' || p_search_attr || '=' || p_search_value || '))',
                  attrs    => l_attrs,
                  attronly => 0,
                  res      => l_message
                );
    retrieve_entries(l_message, l_entries);
    for i in 1 .. l_entries.count loop
      if l_entries(i).attributes.exists(p_username_attr) then
        for j in 1 .. l_entries(i).attributes(p_username_attr).count loop
          l_users.extend();
          l_users(l_users.count) := l_entries(i).attributes(p_username_attr)(j).text;
        end loop;
      end if;
    end loop;

    return l_users;
  end get_users_by_attr;

  function get_users_by_dn(p_dn            in varchar2,
                           p_username_attr in varchar2 default c_attr_username) return t_users is
    l_attrs   dbms_ldap.string_collection;
    l_message dbms_ldap.message;
    l_entries t_entries;
    l_users   t_users := t_users();
  begin
    return get_users_by_attr(c_attr_dn, p_dn, p_username_attr);
  end get_users_by_dn;

  function check_login(p_username in varchar2,
                       p_password in varchar2) return boolean is
  begin
    if g_session is null or g_host is null or g_port is null then
      raise dbms_ldap.invalid_session;
    end if;

    --g_username := p_username;
    --g_password := p_password;
    --connect_ldap;

    g_retval := dbms_ldap.simple_bind_s(ld     => g_session,
                                        dn     => p_username,
                                        passwd => p_password);
    if g_retval = dbms_ldap.success then
      return true;
    else
      return false;
    end if;
  exception when others then
    return false;
  end check_login;
end pkg_ldap;
/