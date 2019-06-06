# plsql-ldap
PL/SQL Package to help managing LDAP connections

## Examples
Retrieve all user attributes

    declare
      l_attr      pkg_ldap.t_attributes;
      l_attr_list pkg_ldap.t_attributes_list;
    begin
      pkg_ldap.set_credentials (
        p_host        => '192.168.0.1',
        p_port        => '389',
        p_username    => 'admin_user',
        p_password    => 'password',
        p_ldap_base   => 'DC=com,DC=mycompany',
        p_wallet_path => '/path/to/wallet',
        p_wallet_pass => 'walletpass',
        p_wallet_mode => 2
      );

      pkg_ldap.connect_ldap;

      pkg_ldap.get_user_attributes(p_username        => 'username',
                                   p_attrib          => null,
                                   p_attributes      => l_attr,
                                   p_attributes_list => l_attr_list);

      for i in 1 .. l_attr_list.count loop
        for j in 1 .. l_attr(l_attr_list(i)).count loop
          if l_attr(l_attr_list(i))(j).type = 'T' then
            dbms_output.put_line(l_attr_list(i) || ': ' || l_attr(l_attr_list(i))(j).text);
          else
            dbms_output.put_line(l_attr_list(i) || ': ' || nvl(dbms_lob.getlength(l_attr(l_attr_list(i))(j).bin), 0));
          end if;
        end loop;
      end loop;

      pkg_ldap.disconnect_ldap;
    end;
    /
