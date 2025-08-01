// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSmbSettingsOutput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the domain that the gateway is joined to.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the status of a gateway that is a member of the Active Directory domain.</p><note>
    /// <p>This field is only used as part of a <code>JoinDomain</code> request. It is not affected by Active Directory connectivity changes that occur after the <code>JoinDomain</code> request succeeds.</p>
    /// </note>
    /// <ul>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Indicates that the <code>JoinDomain</code> operation failed due to an authentication error.</p></li>
    /// <li>
    /// <p><code>DETACHED</code>: Indicates that gateway is not joined to a domain.</p></li>
    /// <li>
    /// <p><code>JOINED</code>: Indicates that the gateway has successfully joined a domain.</p></li>
    /// <li>
    /// <p><code>JOINING</code>: Indicates that a <code>JoinDomain</code> operation is in progress.</p></li>
    /// <li>
    /// <p><code>NETWORK_ERROR</code>: Indicates that <code>JoinDomain</code> operation failed due to a network or connectivity error.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code>: Indicates that the <code>JoinDomain</code> operation failed because the operation didn't complete within the allotted time.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code>: Indicates that the <code>JoinDomain</code> operation failed due to another type of error.</p></li>
    /// </ul>
    pub active_directory_status: ::std::option::Option<crate::types::ActiveDirectoryStatus>,
    /// <p>This value is <code>true</code> if a password for the guest user <code>smbguest</code> is set, otherwise <code>false</code>. Only supported for S3 File Gateways.</p>
    /// <p>Valid Values: <code>true</code> | <code>false</code></p>
    pub smb_guest_password_set: ::std::option::Option<bool>,
    /// <p>The type of security strategy that was specified for file gateway.</p>
    /// <ul>
    /// <li>
    /// <p><code>ClientSpecified</code>: If you choose this option, requests are established based on what is negotiated by the client. This option is recommended when you want to maximize compatibility across different clients in your environment. Supported only for S3 File Gateway.</p></li>
    /// <li>
    /// <p><code>MandatorySigning</code>: If you choose this option, File Gateway only allows connections from SMBv2 or SMBv3 clients that have signing turned on. This option works with SMB clients on Microsoft Windows Vista, Windows Server 2008, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryption</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that have encryption turned on. Both 256-bit and 128-bit algorithms are allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryptionNoAes128</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that use 256-bit AES encryption algorithms. 128-bit algorithms are not allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// </ul>
    pub smb_security_strategy: ::std::option::Option<crate::types::SmbSecurityStrategy>,
    /// <p>The shares on this gateway appear when listing shares. Only supported for S3 File Gateways.</p>
    pub file_shares_visible: ::std::option::Option<bool>,
    /// <p>A list of Active Directory users and groups that have special permissions for SMB file shares on the gateway.</p>
    pub smb_local_groups: ::std::option::Option<crate::types::SmbLocalGroups>,
    _request_id: Option<String>,
}
impl DescribeSmbSettingsOutput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
    /// <p>The name of the domain that the gateway is joined to.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>Indicates the status of a gateway that is a member of the Active Directory domain.</p><note>
    /// <p>This field is only used as part of a <code>JoinDomain</code> request. It is not affected by Active Directory connectivity changes that occur after the <code>JoinDomain</code> request succeeds.</p>
    /// </note>
    /// <ul>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Indicates that the <code>JoinDomain</code> operation failed due to an authentication error.</p></li>
    /// <li>
    /// <p><code>DETACHED</code>: Indicates that gateway is not joined to a domain.</p></li>
    /// <li>
    /// <p><code>JOINED</code>: Indicates that the gateway has successfully joined a domain.</p></li>
    /// <li>
    /// <p><code>JOINING</code>: Indicates that a <code>JoinDomain</code> operation is in progress.</p></li>
    /// <li>
    /// <p><code>NETWORK_ERROR</code>: Indicates that <code>JoinDomain</code> operation failed due to a network or connectivity error.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code>: Indicates that the <code>JoinDomain</code> operation failed because the operation didn't complete within the allotted time.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code>: Indicates that the <code>JoinDomain</code> operation failed due to another type of error.</p></li>
    /// </ul>
    pub fn active_directory_status(&self) -> ::std::option::Option<&crate::types::ActiveDirectoryStatus> {
        self.active_directory_status.as_ref()
    }
    /// <p>This value is <code>true</code> if a password for the guest user <code>smbguest</code> is set, otherwise <code>false</code>. Only supported for S3 File Gateways.</p>
    /// <p>Valid Values: <code>true</code> | <code>false</code></p>
    pub fn smb_guest_password_set(&self) -> ::std::option::Option<bool> {
        self.smb_guest_password_set
    }
    /// <p>The type of security strategy that was specified for file gateway.</p>
    /// <ul>
    /// <li>
    /// <p><code>ClientSpecified</code>: If you choose this option, requests are established based on what is negotiated by the client. This option is recommended when you want to maximize compatibility across different clients in your environment. Supported only for S3 File Gateway.</p></li>
    /// <li>
    /// <p><code>MandatorySigning</code>: If you choose this option, File Gateway only allows connections from SMBv2 or SMBv3 clients that have signing turned on. This option works with SMB clients on Microsoft Windows Vista, Windows Server 2008, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryption</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that have encryption turned on. Both 256-bit and 128-bit algorithms are allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryptionNoAes128</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that use 256-bit AES encryption algorithms. 128-bit algorithms are not allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// </ul>
    pub fn smb_security_strategy(&self) -> ::std::option::Option<&crate::types::SmbSecurityStrategy> {
        self.smb_security_strategy.as_ref()
    }
    /// <p>The shares on this gateway appear when listing shares. Only supported for S3 File Gateways.</p>
    pub fn file_shares_visible(&self) -> ::std::option::Option<bool> {
        self.file_shares_visible
    }
    /// <p>A list of Active Directory users and groups that have special permissions for SMB file shares on the gateway.</p>
    pub fn smb_local_groups(&self) -> ::std::option::Option<&crate::types::SmbLocalGroups> {
        self.smb_local_groups.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeSmbSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeSmbSettingsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeSmbSettingsOutput`](crate::operation::describe_smb_settings::DescribeSmbSettingsOutput).
    pub fn builder() -> crate::operation::describe_smb_settings::builders::DescribeSmbSettingsOutputBuilder {
        crate::operation::describe_smb_settings::builders::DescribeSmbSettingsOutputBuilder::default()
    }
}

/// A builder for [`DescribeSmbSettingsOutput`](crate::operation::describe_smb_settings::DescribeSmbSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSmbSettingsOutputBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) active_directory_status: ::std::option::Option<crate::types::ActiveDirectoryStatus>,
    pub(crate) smb_guest_password_set: ::std::option::Option<bool>,
    pub(crate) smb_security_strategy: ::std::option::Option<crate::types::SmbSecurityStrategy>,
    pub(crate) file_shares_visible: ::std::option::Option<bool>,
    pub(crate) smb_local_groups: ::std::option::Option<crate::types::SmbLocalGroups>,
    _request_id: Option<String>,
}
impl DescribeSmbSettingsOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn set_gateway_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn get_gateway_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_arn
    }
    /// <p>The name of the domain that the gateway is joined to.</p>
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain that the gateway is joined to.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the domain that the gateway is joined to.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>Indicates the status of a gateway that is a member of the Active Directory domain.</p><note>
    /// <p>This field is only used as part of a <code>JoinDomain</code> request. It is not affected by Active Directory connectivity changes that occur after the <code>JoinDomain</code> request succeeds.</p>
    /// </note>
    /// <ul>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Indicates that the <code>JoinDomain</code> operation failed due to an authentication error.</p></li>
    /// <li>
    /// <p><code>DETACHED</code>: Indicates that gateway is not joined to a domain.</p></li>
    /// <li>
    /// <p><code>JOINED</code>: Indicates that the gateway has successfully joined a domain.</p></li>
    /// <li>
    /// <p><code>JOINING</code>: Indicates that a <code>JoinDomain</code> operation is in progress.</p></li>
    /// <li>
    /// <p><code>NETWORK_ERROR</code>: Indicates that <code>JoinDomain</code> operation failed due to a network or connectivity error.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code>: Indicates that the <code>JoinDomain</code> operation failed because the operation didn't complete within the allotted time.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code>: Indicates that the <code>JoinDomain</code> operation failed due to another type of error.</p></li>
    /// </ul>
    pub fn active_directory_status(mut self, input: crate::types::ActiveDirectoryStatus) -> Self {
        self.active_directory_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the status of a gateway that is a member of the Active Directory domain.</p><note>
    /// <p>This field is only used as part of a <code>JoinDomain</code> request. It is not affected by Active Directory connectivity changes that occur after the <code>JoinDomain</code> request succeeds.</p>
    /// </note>
    /// <ul>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Indicates that the <code>JoinDomain</code> operation failed due to an authentication error.</p></li>
    /// <li>
    /// <p><code>DETACHED</code>: Indicates that gateway is not joined to a domain.</p></li>
    /// <li>
    /// <p><code>JOINED</code>: Indicates that the gateway has successfully joined a domain.</p></li>
    /// <li>
    /// <p><code>JOINING</code>: Indicates that a <code>JoinDomain</code> operation is in progress.</p></li>
    /// <li>
    /// <p><code>NETWORK_ERROR</code>: Indicates that <code>JoinDomain</code> operation failed due to a network or connectivity error.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code>: Indicates that the <code>JoinDomain</code> operation failed because the operation didn't complete within the allotted time.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code>: Indicates that the <code>JoinDomain</code> operation failed due to another type of error.</p></li>
    /// </ul>
    pub fn set_active_directory_status(mut self, input: ::std::option::Option<crate::types::ActiveDirectoryStatus>) -> Self {
        self.active_directory_status = input;
        self
    }
    /// <p>Indicates the status of a gateway that is a member of the Active Directory domain.</p><note>
    /// <p>This field is only used as part of a <code>JoinDomain</code> request. It is not affected by Active Directory connectivity changes that occur after the <code>JoinDomain</code> request succeeds.</p>
    /// </note>
    /// <ul>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Indicates that the <code>JoinDomain</code> operation failed due to an authentication error.</p></li>
    /// <li>
    /// <p><code>DETACHED</code>: Indicates that gateway is not joined to a domain.</p></li>
    /// <li>
    /// <p><code>JOINED</code>: Indicates that the gateway has successfully joined a domain.</p></li>
    /// <li>
    /// <p><code>JOINING</code>: Indicates that a <code>JoinDomain</code> operation is in progress.</p></li>
    /// <li>
    /// <p><code>NETWORK_ERROR</code>: Indicates that <code>JoinDomain</code> operation failed due to a network or connectivity error.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code>: Indicates that the <code>JoinDomain</code> operation failed because the operation didn't complete within the allotted time.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code>: Indicates that the <code>JoinDomain</code> operation failed due to another type of error.</p></li>
    /// </ul>
    pub fn get_active_directory_status(&self) -> &::std::option::Option<crate::types::ActiveDirectoryStatus> {
        &self.active_directory_status
    }
    /// <p>This value is <code>true</code> if a password for the guest user <code>smbguest</code> is set, otherwise <code>false</code>. Only supported for S3 File Gateways.</p>
    /// <p>Valid Values: <code>true</code> | <code>false</code></p>
    pub fn smb_guest_password_set(mut self, input: bool) -> Self {
        self.smb_guest_password_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>This value is <code>true</code> if a password for the guest user <code>smbguest</code> is set, otherwise <code>false</code>. Only supported for S3 File Gateways.</p>
    /// <p>Valid Values: <code>true</code> | <code>false</code></p>
    pub fn set_smb_guest_password_set(mut self, input: ::std::option::Option<bool>) -> Self {
        self.smb_guest_password_set = input;
        self
    }
    /// <p>This value is <code>true</code> if a password for the guest user <code>smbguest</code> is set, otherwise <code>false</code>. Only supported for S3 File Gateways.</p>
    /// <p>Valid Values: <code>true</code> | <code>false</code></p>
    pub fn get_smb_guest_password_set(&self) -> &::std::option::Option<bool> {
        &self.smb_guest_password_set
    }
    /// <p>The type of security strategy that was specified for file gateway.</p>
    /// <ul>
    /// <li>
    /// <p><code>ClientSpecified</code>: If you choose this option, requests are established based on what is negotiated by the client. This option is recommended when you want to maximize compatibility across different clients in your environment. Supported only for S3 File Gateway.</p></li>
    /// <li>
    /// <p><code>MandatorySigning</code>: If you choose this option, File Gateway only allows connections from SMBv2 or SMBv3 clients that have signing turned on. This option works with SMB clients on Microsoft Windows Vista, Windows Server 2008, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryption</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that have encryption turned on. Both 256-bit and 128-bit algorithms are allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryptionNoAes128</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that use 256-bit AES encryption algorithms. 128-bit algorithms are not allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// </ul>
    pub fn smb_security_strategy(mut self, input: crate::types::SmbSecurityStrategy) -> Self {
        self.smb_security_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of security strategy that was specified for file gateway.</p>
    /// <ul>
    /// <li>
    /// <p><code>ClientSpecified</code>: If you choose this option, requests are established based on what is negotiated by the client. This option is recommended when you want to maximize compatibility across different clients in your environment. Supported only for S3 File Gateway.</p></li>
    /// <li>
    /// <p><code>MandatorySigning</code>: If you choose this option, File Gateway only allows connections from SMBv2 or SMBv3 clients that have signing turned on. This option works with SMB clients on Microsoft Windows Vista, Windows Server 2008, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryption</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that have encryption turned on. Both 256-bit and 128-bit algorithms are allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryptionNoAes128</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that use 256-bit AES encryption algorithms. 128-bit algorithms are not allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// </ul>
    pub fn set_smb_security_strategy(mut self, input: ::std::option::Option<crate::types::SmbSecurityStrategy>) -> Self {
        self.smb_security_strategy = input;
        self
    }
    /// <p>The type of security strategy that was specified for file gateway.</p>
    /// <ul>
    /// <li>
    /// <p><code>ClientSpecified</code>: If you choose this option, requests are established based on what is negotiated by the client. This option is recommended when you want to maximize compatibility across different clients in your environment. Supported only for S3 File Gateway.</p></li>
    /// <li>
    /// <p><code>MandatorySigning</code>: If you choose this option, File Gateway only allows connections from SMBv2 or SMBv3 clients that have signing turned on. This option works with SMB clients on Microsoft Windows Vista, Windows Server 2008, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryption</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that have encryption turned on. Both 256-bit and 128-bit algorithms are allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// <li>
    /// <p><code>MandatoryEncryptionNoAes128</code>: If you choose this option, File Gateway only allows connections from SMBv3 clients that use 256-bit AES encryption algorithms. 128-bit algorithms are not allowed. This option is recommended for environments that handle sensitive data. It works with SMB clients on Microsoft Windows 8, Windows Server 2012, or later.</p></li>
    /// </ul>
    pub fn get_smb_security_strategy(&self) -> &::std::option::Option<crate::types::SmbSecurityStrategy> {
        &self.smb_security_strategy
    }
    /// <p>The shares on this gateway appear when listing shares. Only supported for S3 File Gateways.</p>
    pub fn file_shares_visible(mut self, input: bool) -> Self {
        self.file_shares_visible = ::std::option::Option::Some(input);
        self
    }
    /// <p>The shares on this gateway appear when listing shares. Only supported for S3 File Gateways.</p>
    pub fn set_file_shares_visible(mut self, input: ::std::option::Option<bool>) -> Self {
        self.file_shares_visible = input;
        self
    }
    /// <p>The shares on this gateway appear when listing shares. Only supported for S3 File Gateways.</p>
    pub fn get_file_shares_visible(&self) -> &::std::option::Option<bool> {
        &self.file_shares_visible
    }
    /// <p>A list of Active Directory users and groups that have special permissions for SMB file shares on the gateway.</p>
    pub fn smb_local_groups(mut self, input: crate::types::SmbLocalGroups) -> Self {
        self.smb_local_groups = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of Active Directory users and groups that have special permissions for SMB file shares on the gateway.</p>
    pub fn set_smb_local_groups(mut self, input: ::std::option::Option<crate::types::SmbLocalGroups>) -> Self {
        self.smb_local_groups = input;
        self
    }
    /// <p>A list of Active Directory users and groups that have special permissions for SMB file shares on the gateway.</p>
    pub fn get_smb_local_groups(&self) -> &::std::option::Option<crate::types::SmbLocalGroups> {
        &self.smb_local_groups
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeSmbSettingsOutput`](crate::operation::describe_smb_settings::DescribeSmbSettingsOutput).
    pub fn build(self) -> crate::operation::describe_smb_settings::DescribeSmbSettingsOutput {
        crate::operation::describe_smb_settings::DescribeSmbSettingsOutput {
            gateway_arn: self.gateway_arn,
            domain_name: self.domain_name,
            active_directory_status: self.active_directory_status,
            smb_guest_password_set: self.smb_guest_password_set,
            smb_security_strategy: self.smb_security_strategy,
            file_shares_visible: self.file_shares_visible,
            smb_local_groups: self.smb_local_groups,
            _request_id: self._request_id,
        }
    }
}
