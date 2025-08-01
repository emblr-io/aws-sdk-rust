// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateLocationSmbInput {
    /// <p>Specifies the ARN of the SMB location that you want to update.</p>
    pub location_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the name of the share exported by your SMB file server where DataSync will read or write data. You can include a subdirectory in the share path (for example, <code>/path/to/subdirectory</code>). Make sure that other SMB clients in your network can also mount this path.</p>
    /// <p>To copy all data in the specified subdirectory, DataSync must be able to mount the SMB share and access all of its data. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub subdirectory: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the domain name or IP address of the SMB file server that your DataSync agent connects to.</p>
    /// <p>Remember the following when configuring this parameter:</p>
    /// <ul>
    /// <li>
    /// <p>You can't specify an IP version 6 (IPv6) address.</p></li>
    /// <li>
    /// <p>If you're using Kerberos authentication, you must specify a domain name.</p></li>
    /// </ul>
    pub server_hostname: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the user name that can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>For information about choosing a user with the right level of access for your transfer, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub user: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the Windows domain name that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right file server.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the password of the user who can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    pub password: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the DataSync agent (or agents) that can connect to your SMB file server. You specify an agent by using its Amazon Resource Name (ARN).</p>
    pub agent_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Specifies the version of the Server Message Block (SMB) protocol that DataSync uses to access an SMB file server.</p>
    pub mount_options: ::std::option::Option<crate::types::SmbMountOptions>,
    /// <p>Specifies the authentication protocol that DataSync uses to connect to your SMB file server. DataSync supports <code>NTLM</code> (default) and <code>KERBEROS</code> authentication.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub authentication_type: ::std::option::Option<crate::types::SmbAuthenticationType>,
    /// <p>Specifies the IPv4 addresses for the DNS servers that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>KERBEROS</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right SMB file server.</p>
    pub dns_ip_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Specifies a Kerberos prinicpal, which is an identity in your Kerberos realm that has permission to access the files, folders, and file metadata in your SMB file server.</p>
    /// <p>A Kerberos principal might look like <code>HOST/kerberosuser@MYDOMAIN.ORG</code>.</p>
    /// <p>Principal names are case sensitive. Your DataSync task execution will fail if the principal that you specify for this parameter doesn’t exactly match the principal that you use to create the keytab file.</p>
    pub kerberos_principal: ::std::option::Option<::std::string::String>,
    /// <p>Specifies your Kerberos key table (keytab) file, which includes mappings between your Kerberos principal and encryption keys.</p>
    /// <p>To avoid task execution errors, make sure that the Kerberos principal that you use to create the keytab file matches exactly what you specify for <code>KerberosPrincipal</code>.</p>
    pub kerberos_keytab: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Specifies a Kerberos configuration file (<code>krb5.conf</code>) that defines your Kerberos realm configuration.</p>
    /// <p>The file must be base64 encoded. If you're using the CLI, the encoding is done for you.</p>
    pub kerberos_krb5_conf: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl UpdateLocationSmbInput {
    /// <p>Specifies the ARN of the SMB location that you want to update.</p>
    pub fn location_arn(&self) -> ::std::option::Option<&str> {
        self.location_arn.as_deref()
    }
    /// <p>Specifies the name of the share exported by your SMB file server where DataSync will read or write data. You can include a subdirectory in the share path (for example, <code>/path/to/subdirectory</code>). Make sure that other SMB clients in your network can also mount this path.</p>
    /// <p>To copy all data in the specified subdirectory, DataSync must be able to mount the SMB share and access all of its data. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn subdirectory(&self) -> ::std::option::Option<&str> {
        self.subdirectory.as_deref()
    }
    /// <p>Specifies the domain name or IP address of the SMB file server that your DataSync agent connects to.</p>
    /// <p>Remember the following when configuring this parameter:</p>
    /// <ul>
    /// <li>
    /// <p>You can't specify an IP version 6 (IPv6) address.</p></li>
    /// <li>
    /// <p>If you're using Kerberos authentication, you must specify a domain name.</p></li>
    /// </ul>
    pub fn server_hostname(&self) -> ::std::option::Option<&str> {
        self.server_hostname.as_deref()
    }
    /// <p>Specifies the user name that can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>For information about choosing a user with the right level of access for your transfer, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn user(&self) -> ::std::option::Option<&str> {
        self.user.as_deref()
    }
    /// <p>Specifies the Windows domain name that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right file server.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>Specifies the password of the user who can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
    /// <p>Specifies the DataSync agent (or agents) that can connect to your SMB file server. You specify an agent by using its Amazon Resource Name (ARN).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.agent_arns.is_none()`.
    pub fn agent_arns(&self) -> &[::std::string::String] {
        self.agent_arns.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the version of the Server Message Block (SMB) protocol that DataSync uses to access an SMB file server.</p>
    pub fn mount_options(&self) -> ::std::option::Option<&crate::types::SmbMountOptions> {
        self.mount_options.as_ref()
    }
    /// <p>Specifies the authentication protocol that DataSync uses to connect to your SMB file server. DataSync supports <code>NTLM</code> (default) and <code>KERBEROS</code> authentication.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn authentication_type(&self) -> ::std::option::Option<&crate::types::SmbAuthenticationType> {
        self.authentication_type.as_ref()
    }
    /// <p>Specifies the IPv4 addresses for the DNS servers that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>KERBEROS</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right SMB file server.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dns_ip_addresses.is_none()`.
    pub fn dns_ip_addresses(&self) -> &[::std::string::String] {
        self.dns_ip_addresses.as_deref().unwrap_or_default()
    }
    /// <p>Specifies a Kerberos prinicpal, which is an identity in your Kerberos realm that has permission to access the files, folders, and file metadata in your SMB file server.</p>
    /// <p>A Kerberos principal might look like <code>HOST/kerberosuser@MYDOMAIN.ORG</code>.</p>
    /// <p>Principal names are case sensitive. Your DataSync task execution will fail if the principal that you specify for this parameter doesn’t exactly match the principal that you use to create the keytab file.</p>
    pub fn kerberos_principal(&self) -> ::std::option::Option<&str> {
        self.kerberos_principal.as_deref()
    }
    /// <p>Specifies your Kerberos key table (keytab) file, which includes mappings between your Kerberos principal and encryption keys.</p>
    /// <p>To avoid task execution errors, make sure that the Kerberos principal that you use to create the keytab file matches exactly what you specify for <code>KerberosPrincipal</code>.</p>
    pub fn kerberos_keytab(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.kerberos_keytab.as_ref()
    }
    /// <p>Specifies a Kerberos configuration file (<code>krb5.conf</code>) that defines your Kerberos realm configuration.</p>
    /// <p>The file must be base64 encoded. If you're using the CLI, the encoding is done for you.</p>
    pub fn kerberos_krb5_conf(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.kerberos_krb5_conf.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateLocationSmbInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateLocationSmbInput");
        formatter.field("location_arn", &self.location_arn);
        formatter.field("subdirectory", &self.subdirectory);
        formatter.field("server_hostname", &self.server_hostname);
        formatter.field("user", &self.user);
        formatter.field("domain", &self.domain);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("agent_arns", &self.agent_arns);
        formatter.field("mount_options", &self.mount_options);
        formatter.field("authentication_type", &self.authentication_type);
        formatter.field("dns_ip_addresses", &self.dns_ip_addresses);
        formatter.field("kerberos_principal", &self.kerberos_principal);
        formatter.field("kerberos_keytab", &self.kerberos_keytab);
        formatter.field("kerberos_krb5_conf", &self.kerberos_krb5_conf);
        formatter.finish()
    }
}
impl UpdateLocationSmbInput {
    /// Creates a new builder-style object to manufacture [`UpdateLocationSmbInput`](crate::operation::update_location_smb::UpdateLocationSmbInput).
    pub fn builder() -> crate::operation::update_location_smb::builders::UpdateLocationSmbInputBuilder {
        crate::operation::update_location_smb::builders::UpdateLocationSmbInputBuilder::default()
    }
}

/// A builder for [`UpdateLocationSmbInput`](crate::operation::update_location_smb::UpdateLocationSmbInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateLocationSmbInputBuilder {
    pub(crate) location_arn: ::std::option::Option<::std::string::String>,
    pub(crate) subdirectory: ::std::option::Option<::std::string::String>,
    pub(crate) server_hostname: ::std::option::Option<::std::string::String>,
    pub(crate) user: ::std::option::Option<::std::string::String>,
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
    pub(crate) agent_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) mount_options: ::std::option::Option<crate::types::SmbMountOptions>,
    pub(crate) authentication_type: ::std::option::Option<crate::types::SmbAuthenticationType>,
    pub(crate) dns_ip_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) kerberos_principal: ::std::option::Option<::std::string::String>,
    pub(crate) kerberos_keytab: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) kerberos_krb5_conf: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl UpdateLocationSmbInputBuilder {
    /// <p>Specifies the ARN of the SMB location that you want to update.</p>
    /// This field is required.
    pub fn location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN of the SMB location that you want to update.</p>
    pub fn set_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_arn = input;
        self
    }
    /// <p>Specifies the ARN of the SMB location that you want to update.</p>
    pub fn get_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_arn
    }
    /// <p>Specifies the name of the share exported by your SMB file server where DataSync will read or write data. You can include a subdirectory in the share path (for example, <code>/path/to/subdirectory</code>). Make sure that other SMB clients in your network can also mount this path.</p>
    /// <p>To copy all data in the specified subdirectory, DataSync must be able to mount the SMB share and access all of its data. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn subdirectory(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subdirectory = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the name of the share exported by your SMB file server where DataSync will read or write data. You can include a subdirectory in the share path (for example, <code>/path/to/subdirectory</code>). Make sure that other SMB clients in your network can also mount this path.</p>
    /// <p>To copy all data in the specified subdirectory, DataSync must be able to mount the SMB share and access all of its data. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn set_subdirectory(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subdirectory = input;
        self
    }
    /// <p>Specifies the name of the share exported by your SMB file server where DataSync will read or write data. You can include a subdirectory in the share path (for example, <code>/path/to/subdirectory</code>). Make sure that other SMB clients in your network can also mount this path.</p>
    /// <p>To copy all data in the specified subdirectory, DataSync must be able to mount the SMB share and access all of its data. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn get_subdirectory(&self) -> &::std::option::Option<::std::string::String> {
        &self.subdirectory
    }
    /// <p>Specifies the domain name or IP address of the SMB file server that your DataSync agent connects to.</p>
    /// <p>Remember the following when configuring this parameter:</p>
    /// <ul>
    /// <li>
    /// <p>You can't specify an IP version 6 (IPv6) address.</p></li>
    /// <li>
    /// <p>If you're using Kerberos authentication, you must specify a domain name.</p></li>
    /// </ul>
    pub fn server_hostname(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_hostname = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the domain name or IP address of the SMB file server that your DataSync agent connects to.</p>
    /// <p>Remember the following when configuring this parameter:</p>
    /// <ul>
    /// <li>
    /// <p>You can't specify an IP version 6 (IPv6) address.</p></li>
    /// <li>
    /// <p>If you're using Kerberos authentication, you must specify a domain name.</p></li>
    /// </ul>
    pub fn set_server_hostname(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_hostname = input;
        self
    }
    /// <p>Specifies the domain name or IP address of the SMB file server that your DataSync agent connects to.</p>
    /// <p>Remember the following when configuring this parameter:</p>
    /// <ul>
    /// <li>
    /// <p>You can't specify an IP version 6 (IPv6) address.</p></li>
    /// <li>
    /// <p>If you're using Kerberos authentication, you must specify a domain name.</p></li>
    /// </ul>
    pub fn get_server_hostname(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_hostname
    }
    /// <p>Specifies the user name that can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>For information about choosing a user with the right level of access for your transfer, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn user(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the user name that can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>For information about choosing a user with the right level of access for your transfer, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn set_user(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user = input;
        self
    }
    /// <p>Specifies the user name that can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>For information about choosing a user with the right level of access for your transfer, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn get_user(&self) -> &::std::option::Option<::std::string::String> {
        &self.user
    }
    /// <p>Specifies the Windows domain name that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right file server.</p>
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Windows domain name that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right file server.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>Specifies the Windows domain name that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right file server.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// <p>Specifies the password of the user who can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the password of the user who can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>Specifies the password of the user who can mount your SMB file server and has permission to access the files and folders involved in your transfer. This parameter applies only if <code>AuthenticationType</code> is set to <code>NTLM</code>.</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// Appends an item to `agent_arns`.
    ///
    /// To override the contents of this collection use [`set_agent_arns`](Self::set_agent_arns).
    ///
    /// <p>Specifies the DataSync agent (or agents) that can connect to your SMB file server. You specify an agent by using its Amazon Resource Name (ARN).</p>
    pub fn agent_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.agent_arns.unwrap_or_default();
        v.push(input.into());
        self.agent_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the DataSync agent (or agents) that can connect to your SMB file server. You specify an agent by using its Amazon Resource Name (ARN).</p>
    pub fn set_agent_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.agent_arns = input;
        self
    }
    /// <p>Specifies the DataSync agent (or agents) that can connect to your SMB file server. You specify an agent by using its Amazon Resource Name (ARN).</p>
    pub fn get_agent_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.agent_arns
    }
    /// <p>Specifies the version of the Server Message Block (SMB) protocol that DataSync uses to access an SMB file server.</p>
    pub fn mount_options(mut self, input: crate::types::SmbMountOptions) -> Self {
        self.mount_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the version of the Server Message Block (SMB) protocol that DataSync uses to access an SMB file server.</p>
    pub fn set_mount_options(mut self, input: ::std::option::Option<crate::types::SmbMountOptions>) -> Self {
        self.mount_options = input;
        self
    }
    /// <p>Specifies the version of the Server Message Block (SMB) protocol that DataSync uses to access an SMB file server.</p>
    pub fn get_mount_options(&self) -> &::std::option::Option<crate::types::SmbMountOptions> {
        &self.mount_options
    }
    /// <p>Specifies the authentication protocol that DataSync uses to connect to your SMB file server. DataSync supports <code>NTLM</code> (default) and <code>KERBEROS</code> authentication.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn authentication_type(mut self, input: crate::types::SmbAuthenticationType) -> Self {
        self.authentication_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the authentication protocol that DataSync uses to connect to your SMB file server. DataSync supports <code>NTLM</code> (default) and <code>KERBEROS</code> authentication.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn set_authentication_type(mut self, input: ::std::option::Option<crate::types::SmbAuthenticationType>) -> Self {
        self.authentication_type = input;
        self
    }
    /// <p>Specifies the authentication protocol that DataSync uses to connect to your SMB file server. DataSync supports <code>NTLM</code> (default) and <code>KERBEROS</code> authentication.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-smb-location.html#configuring-smb-permissions">Providing DataSync access to SMB file servers</a>.</p>
    pub fn get_authentication_type(&self) -> &::std::option::Option<crate::types::SmbAuthenticationType> {
        &self.authentication_type
    }
    /// Appends an item to `dns_ip_addresses`.
    ///
    /// To override the contents of this collection use [`set_dns_ip_addresses`](Self::set_dns_ip_addresses).
    ///
    /// <p>Specifies the IPv4 addresses for the DNS servers that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>KERBEROS</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right SMB file server.</p>
    pub fn dns_ip_addresses(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.dns_ip_addresses.unwrap_or_default();
        v.push(input.into());
        self.dns_ip_addresses = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the IPv4 addresses for the DNS servers that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>KERBEROS</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right SMB file server.</p>
    pub fn set_dns_ip_addresses(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.dns_ip_addresses = input;
        self
    }
    /// <p>Specifies the IPv4 addresses for the DNS servers that your SMB file server belongs to. This parameter applies only if <code>AuthenticationType</code> is set to <code>KERBEROS</code>.</p>
    /// <p>If you have multiple domains in your environment, configuring this parameter makes sure that DataSync connects to the right SMB file server.</p>
    pub fn get_dns_ip_addresses(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.dns_ip_addresses
    }
    /// <p>Specifies a Kerberos prinicpal, which is an identity in your Kerberos realm that has permission to access the files, folders, and file metadata in your SMB file server.</p>
    /// <p>A Kerberos principal might look like <code>HOST/kerberosuser@MYDOMAIN.ORG</code>.</p>
    /// <p>Principal names are case sensitive. Your DataSync task execution will fail if the principal that you specify for this parameter doesn’t exactly match the principal that you use to create the keytab file.</p>
    pub fn kerberos_principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kerberos_principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a Kerberos prinicpal, which is an identity in your Kerberos realm that has permission to access the files, folders, and file metadata in your SMB file server.</p>
    /// <p>A Kerberos principal might look like <code>HOST/kerberosuser@MYDOMAIN.ORG</code>.</p>
    /// <p>Principal names are case sensitive. Your DataSync task execution will fail if the principal that you specify for this parameter doesn’t exactly match the principal that you use to create the keytab file.</p>
    pub fn set_kerberos_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kerberos_principal = input;
        self
    }
    /// <p>Specifies a Kerberos prinicpal, which is an identity in your Kerberos realm that has permission to access the files, folders, and file metadata in your SMB file server.</p>
    /// <p>A Kerberos principal might look like <code>HOST/kerberosuser@MYDOMAIN.ORG</code>.</p>
    /// <p>Principal names are case sensitive. Your DataSync task execution will fail if the principal that you specify for this parameter doesn’t exactly match the principal that you use to create the keytab file.</p>
    pub fn get_kerberos_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.kerberos_principal
    }
    /// <p>Specifies your Kerberos key table (keytab) file, which includes mappings between your Kerberos principal and encryption keys.</p>
    /// <p>To avoid task execution errors, make sure that the Kerberos principal that you use to create the keytab file matches exactly what you specify for <code>KerberosPrincipal</code>.</p>
    pub fn kerberos_keytab(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.kerberos_keytab = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies your Kerberos key table (keytab) file, which includes mappings between your Kerberos principal and encryption keys.</p>
    /// <p>To avoid task execution errors, make sure that the Kerberos principal that you use to create the keytab file matches exactly what you specify for <code>KerberosPrincipal</code>.</p>
    pub fn set_kerberos_keytab(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.kerberos_keytab = input;
        self
    }
    /// <p>Specifies your Kerberos key table (keytab) file, which includes mappings between your Kerberos principal and encryption keys.</p>
    /// <p>To avoid task execution errors, make sure that the Kerberos principal that you use to create the keytab file matches exactly what you specify for <code>KerberosPrincipal</code>.</p>
    pub fn get_kerberos_keytab(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.kerberos_keytab
    }
    /// <p>Specifies a Kerberos configuration file (<code>krb5.conf</code>) that defines your Kerberos realm configuration.</p>
    /// <p>The file must be base64 encoded. If you're using the CLI, the encoding is done for you.</p>
    pub fn kerberos_krb5_conf(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.kerberos_krb5_conf = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a Kerberos configuration file (<code>krb5.conf</code>) that defines your Kerberos realm configuration.</p>
    /// <p>The file must be base64 encoded. If you're using the CLI, the encoding is done for you.</p>
    pub fn set_kerberos_krb5_conf(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.kerberos_krb5_conf = input;
        self
    }
    /// <p>Specifies a Kerberos configuration file (<code>krb5.conf</code>) that defines your Kerberos realm configuration.</p>
    /// <p>The file must be base64 encoded. If you're using the CLI, the encoding is done for you.</p>
    pub fn get_kerberos_krb5_conf(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.kerberos_krb5_conf
    }
    /// Consumes the builder and constructs a [`UpdateLocationSmbInput`](crate::operation::update_location_smb::UpdateLocationSmbInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_location_smb::UpdateLocationSmbInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_location_smb::UpdateLocationSmbInput {
            location_arn: self.location_arn,
            subdirectory: self.subdirectory,
            server_hostname: self.server_hostname,
            user: self.user,
            domain: self.domain,
            password: self.password,
            agent_arns: self.agent_arns,
            mount_options: self.mount_options,
            authentication_type: self.authentication_type,
            dns_ip_addresses: self.dns_ip_addresses,
            kerberos_principal: self.kerberos_principal,
            kerberos_keytab: self.kerberos_keytab,
            kerberos_krb5_conf: self.kerberos_krb5_conf,
        })
    }
}
impl ::std::fmt::Debug for UpdateLocationSmbInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateLocationSmbInputBuilder");
        formatter.field("location_arn", &self.location_arn);
        formatter.field("subdirectory", &self.subdirectory);
        formatter.field("server_hostname", &self.server_hostname);
        formatter.field("user", &self.user);
        formatter.field("domain", &self.domain);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("agent_arns", &self.agent_arns);
        formatter.field("mount_options", &self.mount_options);
        formatter.field("authentication_type", &self.authentication_type);
        formatter.field("dns_ip_addresses", &self.dns_ip_addresses);
        formatter.field("kerberos_principal", &self.kerberos_principal);
        formatter.field("kerberos_keytab", &self.kerberos_keytab);
        formatter.field("kerberos_krb5_conf", &self.kerberos_krb5_conf);
        formatter.finish()
    }
}
