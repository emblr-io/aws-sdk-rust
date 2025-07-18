// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response to a successful <code>AssumeRoleWithSAML</code> request, including temporary Amazon Web Services credentials that can be used to make Amazon Web Services requests.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AssumeRoleWithSamlOutput {
    /// <p>The temporary security credentials, which include an access key ID, a secret access key, and a security (or session) token.</p><note>
    /// <p>The size of the security token that STS API operations return is not fixed. We strongly recommend that you make no assumptions about the maximum size.</p>
    /// </note>
    pub credentials: ::std::option::Option<crate::types::Credentials>,
    /// <p>The identifiers for the temporary security credentials that the operation returns.</p>
    pub assumed_role_user: ::std::option::Option<crate::types::AssumedRoleUser>,
    /// <p>A percentage value that indicates the packed size of the session policies and session tags combined passed in the request. The request fails if the packed size is greater than 100 percent, which means the policies and tags exceeded the allowed space.</p>
    pub packed_policy_size: ::std::option::Option<i32>,
    /// <p>The value of the <code>NameID</code> element in the <code>Subject</code> element of the SAML assertion.</p>
    pub subject: ::std::option::Option<::std::string::String>,
    /// <p>The format of the name ID, as defined by the <code>Format</code> attribute in the <code>NameID</code> element of the SAML assertion. Typical examples of the format are <code>transient</code> or <code>persistent</code>.</p>
    /// <p>If the format includes the prefix <code>urn:oasis:names:tc:SAML:2.0:nameid-format</code>, that prefix is removed. For example, <code>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</code> is returned as <code>transient</code>. If the format includes any other prefix, the format is returned with no modifications.</p>
    pub subject_type: ::std::option::Option<::std::string::String>,
    /// <p>The value of the <code>Issuer</code> element of the SAML assertion.</p>
    pub issuer: ::std::option::Option<::std::string::String>,
    /// <p>The value of the <code>Recipient</code> attribute of the <code>SubjectConfirmationData</code> element of the SAML assertion.</p>
    pub audience: ::std::option::Option<::std::string::String>,
    /// <p>A hash value based on the concatenation of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The <code>Issuer</code> response value.</p></li>
    /// <li>
    /// <p>The Amazon Web Services account ID.</p></li>
    /// <li>
    /// <p>The friendly name (the last part of the ARN) of the SAML provider in IAM.</p></li>
    /// </ul>
    /// <p>The combination of <code>NameQualifier</code> and <code>Subject</code> can be used to uniquely identify a user.</p>
    /// <p>The following pseudocode shows how the hash value is calculated:</p>
    /// <p><code>BASE64 ( SHA1 ( "https://example.com/saml" + "123456789012" + "/MySAMLIdP" ) )</code></p>
    pub name_qualifier: ::std::option::Option<::std::string::String>,
    /// <p>The value in the <code>SourceIdentity</code> attribute in the SAML assertion. The source identity value persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#iam-term-role-chaining">chained role</a> sessions.</p>
    /// <p>You can require users to set a source identity value when they assume a role. You do this by using the <code>sts:SourceIdentity</code> condition key in a role trust policy. That way, actions that are taken with the role are associated with that user. After the source identity is set, the value cannot be changed. It is present in the request for all actions that are taken by the role and persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#id_roles_terms-and-concepts">chained role</a> sessions. You can configure your SAML identity provider to use an attribute associated with your users, like user name or email, as the source identity when calling <code>AssumeRoleWithSAML</code>. You do this by adding an attribute to the SAML assertion. For more information about using source identity, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html">Monitor and control actions taken with assumed roles</a> in the <i>IAM User Guide</i>.</p>
    /// <p>The regex used to validate this parameter is a string of characters consisting of upper- and lower-case alphanumeric characters with no spaces. You can also include underscores or any of the following characters: =,.@-</p>
    pub source_identity: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AssumeRoleWithSamlOutput {
    /// <p>The temporary security credentials, which include an access key ID, a secret access key, and a security (or session) token.</p><note>
    /// <p>The size of the security token that STS API operations return is not fixed. We strongly recommend that you make no assumptions about the maximum size.</p>
    /// </note>
    pub fn credentials(&self) -> ::std::option::Option<&crate::types::Credentials> {
        self.credentials.as_ref()
    }
    /// <p>The identifiers for the temporary security credentials that the operation returns.</p>
    pub fn assumed_role_user(&self) -> ::std::option::Option<&crate::types::AssumedRoleUser> {
        self.assumed_role_user.as_ref()
    }
    /// <p>A percentage value that indicates the packed size of the session policies and session tags combined passed in the request. The request fails if the packed size is greater than 100 percent, which means the policies and tags exceeded the allowed space.</p>
    pub fn packed_policy_size(&self) -> ::std::option::Option<i32> {
        self.packed_policy_size
    }
    /// <p>The value of the <code>NameID</code> element in the <code>Subject</code> element of the SAML assertion.</p>
    pub fn subject(&self) -> ::std::option::Option<&str> {
        self.subject.as_deref()
    }
    /// <p>The format of the name ID, as defined by the <code>Format</code> attribute in the <code>NameID</code> element of the SAML assertion. Typical examples of the format are <code>transient</code> or <code>persistent</code>.</p>
    /// <p>If the format includes the prefix <code>urn:oasis:names:tc:SAML:2.0:nameid-format</code>, that prefix is removed. For example, <code>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</code> is returned as <code>transient</code>. If the format includes any other prefix, the format is returned with no modifications.</p>
    pub fn subject_type(&self) -> ::std::option::Option<&str> {
        self.subject_type.as_deref()
    }
    /// <p>The value of the <code>Issuer</code> element of the SAML assertion.</p>
    pub fn issuer(&self) -> ::std::option::Option<&str> {
        self.issuer.as_deref()
    }
    /// <p>The value of the <code>Recipient</code> attribute of the <code>SubjectConfirmationData</code> element of the SAML assertion.</p>
    pub fn audience(&self) -> ::std::option::Option<&str> {
        self.audience.as_deref()
    }
    /// <p>A hash value based on the concatenation of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The <code>Issuer</code> response value.</p></li>
    /// <li>
    /// <p>The Amazon Web Services account ID.</p></li>
    /// <li>
    /// <p>The friendly name (the last part of the ARN) of the SAML provider in IAM.</p></li>
    /// </ul>
    /// <p>The combination of <code>NameQualifier</code> and <code>Subject</code> can be used to uniquely identify a user.</p>
    /// <p>The following pseudocode shows how the hash value is calculated:</p>
    /// <p><code>BASE64 ( SHA1 ( "https://example.com/saml" + "123456789012" + "/MySAMLIdP" ) )</code></p>
    pub fn name_qualifier(&self) -> ::std::option::Option<&str> {
        self.name_qualifier.as_deref()
    }
    /// <p>The value in the <code>SourceIdentity</code> attribute in the SAML assertion. The source identity value persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#iam-term-role-chaining">chained role</a> sessions.</p>
    /// <p>You can require users to set a source identity value when they assume a role. You do this by using the <code>sts:SourceIdentity</code> condition key in a role trust policy. That way, actions that are taken with the role are associated with that user. After the source identity is set, the value cannot be changed. It is present in the request for all actions that are taken by the role and persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#id_roles_terms-and-concepts">chained role</a> sessions. You can configure your SAML identity provider to use an attribute associated with your users, like user name or email, as the source identity when calling <code>AssumeRoleWithSAML</code>. You do this by adding an attribute to the SAML assertion. For more information about using source identity, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html">Monitor and control actions taken with assumed roles</a> in the <i>IAM User Guide</i>.</p>
    /// <p>The regex used to validate this parameter is a string of characters consisting of upper- and lower-case alphanumeric characters with no spaces. You can also include underscores or any of the following characters: =,.@-</p>
    pub fn source_identity(&self) -> ::std::option::Option<&str> {
        self.source_identity.as_deref()
    }
}
impl ::std::fmt::Debug for AssumeRoleWithSamlOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AssumeRoleWithSamlOutput");
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("assumed_role_user", &self.assumed_role_user);
        formatter.field("packed_policy_size", &self.packed_policy_size);
        formatter.field("subject", &self.subject);
        formatter.field("subject_type", &self.subject_type);
        formatter.field("issuer", &self.issuer);
        formatter.field("audience", &self.audience);
        formatter.field("name_qualifier", &self.name_qualifier);
        formatter.field("source_identity", &self.source_identity);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for AssumeRoleWithSamlOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssumeRoleWithSamlOutput {
    /// Creates a new builder-style object to manufacture [`AssumeRoleWithSamlOutput`](crate::operation::assume_role_with_saml::AssumeRoleWithSamlOutput).
    pub fn builder() -> crate::operation::assume_role_with_saml::builders::AssumeRoleWithSamlOutputBuilder {
        crate::operation::assume_role_with_saml::builders::AssumeRoleWithSamlOutputBuilder::default()
    }
}

/// A builder for [`AssumeRoleWithSamlOutput`](crate::operation::assume_role_with_saml::AssumeRoleWithSamlOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AssumeRoleWithSamlOutputBuilder {
    pub(crate) credentials: ::std::option::Option<crate::types::Credentials>,
    pub(crate) assumed_role_user: ::std::option::Option<crate::types::AssumedRoleUser>,
    pub(crate) packed_policy_size: ::std::option::Option<i32>,
    pub(crate) subject: ::std::option::Option<::std::string::String>,
    pub(crate) subject_type: ::std::option::Option<::std::string::String>,
    pub(crate) issuer: ::std::option::Option<::std::string::String>,
    pub(crate) audience: ::std::option::Option<::std::string::String>,
    pub(crate) name_qualifier: ::std::option::Option<::std::string::String>,
    pub(crate) source_identity: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AssumeRoleWithSamlOutputBuilder {
    /// <p>The temporary security credentials, which include an access key ID, a secret access key, and a security (or session) token.</p><note>
    /// <p>The size of the security token that STS API operations return is not fixed. We strongly recommend that you make no assumptions about the maximum size.</p>
    /// </note>
    pub fn credentials(mut self, input: crate::types::Credentials) -> Self {
        self.credentials = ::std::option::Option::Some(input);
        self
    }
    /// <p>The temporary security credentials, which include an access key ID, a secret access key, and a security (or session) token.</p><note>
    /// <p>The size of the security token that STS API operations return is not fixed. We strongly recommend that you make no assumptions about the maximum size.</p>
    /// </note>
    pub fn set_credentials(mut self, input: ::std::option::Option<crate::types::Credentials>) -> Self {
        self.credentials = input;
        self
    }
    /// <p>The temporary security credentials, which include an access key ID, a secret access key, and a security (or session) token.</p><note>
    /// <p>The size of the security token that STS API operations return is not fixed. We strongly recommend that you make no assumptions about the maximum size.</p>
    /// </note>
    pub fn get_credentials(&self) -> &::std::option::Option<crate::types::Credentials> {
        &self.credentials
    }
    /// <p>The identifiers for the temporary security credentials that the operation returns.</p>
    pub fn assumed_role_user(mut self, input: crate::types::AssumedRoleUser) -> Self {
        self.assumed_role_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identifiers for the temporary security credentials that the operation returns.</p>
    pub fn set_assumed_role_user(mut self, input: ::std::option::Option<crate::types::AssumedRoleUser>) -> Self {
        self.assumed_role_user = input;
        self
    }
    /// <p>The identifiers for the temporary security credentials that the operation returns.</p>
    pub fn get_assumed_role_user(&self) -> &::std::option::Option<crate::types::AssumedRoleUser> {
        &self.assumed_role_user
    }
    /// <p>A percentage value that indicates the packed size of the session policies and session tags combined passed in the request. The request fails if the packed size is greater than 100 percent, which means the policies and tags exceeded the allowed space.</p>
    pub fn packed_policy_size(mut self, input: i32) -> Self {
        self.packed_policy_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>A percentage value that indicates the packed size of the session policies and session tags combined passed in the request. The request fails if the packed size is greater than 100 percent, which means the policies and tags exceeded the allowed space.</p>
    pub fn set_packed_policy_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.packed_policy_size = input;
        self
    }
    /// <p>A percentage value that indicates the packed size of the session policies and session tags combined passed in the request. The request fails if the packed size is greater than 100 percent, which means the policies and tags exceeded the allowed space.</p>
    pub fn get_packed_policy_size(&self) -> &::std::option::Option<i32> {
        &self.packed_policy_size
    }
    /// <p>The value of the <code>NameID</code> element in the <code>Subject</code> element of the SAML assertion.</p>
    pub fn subject(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the <code>NameID</code> element in the <code>Subject</code> element of the SAML assertion.</p>
    pub fn set_subject(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject = input;
        self
    }
    /// <p>The value of the <code>NameID</code> element in the <code>Subject</code> element of the SAML assertion.</p>
    pub fn get_subject(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject
    }
    /// <p>The format of the name ID, as defined by the <code>Format</code> attribute in the <code>NameID</code> element of the SAML assertion. Typical examples of the format are <code>transient</code> or <code>persistent</code>.</p>
    /// <p>If the format includes the prefix <code>urn:oasis:names:tc:SAML:2.0:nameid-format</code>, that prefix is removed. For example, <code>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</code> is returned as <code>transient</code>. If the format includes any other prefix, the format is returned with no modifications.</p>
    pub fn subject_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The format of the name ID, as defined by the <code>Format</code> attribute in the <code>NameID</code> element of the SAML assertion. Typical examples of the format are <code>transient</code> or <code>persistent</code>.</p>
    /// <p>If the format includes the prefix <code>urn:oasis:names:tc:SAML:2.0:nameid-format</code>, that prefix is removed. For example, <code>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</code> is returned as <code>transient</code>. If the format includes any other prefix, the format is returned with no modifications.</p>
    pub fn set_subject_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject_type = input;
        self
    }
    /// <p>The format of the name ID, as defined by the <code>Format</code> attribute in the <code>NameID</code> element of the SAML assertion. Typical examples of the format are <code>transient</code> or <code>persistent</code>.</p>
    /// <p>If the format includes the prefix <code>urn:oasis:names:tc:SAML:2.0:nameid-format</code>, that prefix is removed. For example, <code>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</code> is returned as <code>transient</code>. If the format includes any other prefix, the format is returned with no modifications.</p>
    pub fn get_subject_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject_type
    }
    /// <p>The value of the <code>Issuer</code> element of the SAML assertion.</p>
    pub fn issuer(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.issuer = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the <code>Issuer</code> element of the SAML assertion.</p>
    pub fn set_issuer(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.issuer = input;
        self
    }
    /// <p>The value of the <code>Issuer</code> element of the SAML assertion.</p>
    pub fn get_issuer(&self) -> &::std::option::Option<::std::string::String> {
        &self.issuer
    }
    /// <p>The value of the <code>Recipient</code> attribute of the <code>SubjectConfirmationData</code> element of the SAML assertion.</p>
    pub fn audience(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.audience = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the <code>Recipient</code> attribute of the <code>SubjectConfirmationData</code> element of the SAML assertion.</p>
    pub fn set_audience(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.audience = input;
        self
    }
    /// <p>The value of the <code>Recipient</code> attribute of the <code>SubjectConfirmationData</code> element of the SAML assertion.</p>
    pub fn get_audience(&self) -> &::std::option::Option<::std::string::String> {
        &self.audience
    }
    /// <p>A hash value based on the concatenation of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The <code>Issuer</code> response value.</p></li>
    /// <li>
    /// <p>The Amazon Web Services account ID.</p></li>
    /// <li>
    /// <p>The friendly name (the last part of the ARN) of the SAML provider in IAM.</p></li>
    /// </ul>
    /// <p>The combination of <code>NameQualifier</code> and <code>Subject</code> can be used to uniquely identify a user.</p>
    /// <p>The following pseudocode shows how the hash value is calculated:</p>
    /// <p><code>BASE64 ( SHA1 ( "https://example.com/saml" + "123456789012" + "/MySAMLIdP" ) )</code></p>
    pub fn name_qualifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name_qualifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A hash value based on the concatenation of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The <code>Issuer</code> response value.</p></li>
    /// <li>
    /// <p>The Amazon Web Services account ID.</p></li>
    /// <li>
    /// <p>The friendly name (the last part of the ARN) of the SAML provider in IAM.</p></li>
    /// </ul>
    /// <p>The combination of <code>NameQualifier</code> and <code>Subject</code> can be used to uniquely identify a user.</p>
    /// <p>The following pseudocode shows how the hash value is calculated:</p>
    /// <p><code>BASE64 ( SHA1 ( "https://example.com/saml" + "123456789012" + "/MySAMLIdP" ) )</code></p>
    pub fn set_name_qualifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name_qualifier = input;
        self
    }
    /// <p>A hash value based on the concatenation of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The <code>Issuer</code> response value.</p></li>
    /// <li>
    /// <p>The Amazon Web Services account ID.</p></li>
    /// <li>
    /// <p>The friendly name (the last part of the ARN) of the SAML provider in IAM.</p></li>
    /// </ul>
    /// <p>The combination of <code>NameQualifier</code> and <code>Subject</code> can be used to uniquely identify a user.</p>
    /// <p>The following pseudocode shows how the hash value is calculated:</p>
    /// <p><code>BASE64 ( SHA1 ( "https://example.com/saml" + "123456789012" + "/MySAMLIdP" ) )</code></p>
    pub fn get_name_qualifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.name_qualifier
    }
    /// <p>The value in the <code>SourceIdentity</code> attribute in the SAML assertion. The source identity value persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#iam-term-role-chaining">chained role</a> sessions.</p>
    /// <p>You can require users to set a source identity value when they assume a role. You do this by using the <code>sts:SourceIdentity</code> condition key in a role trust policy. That way, actions that are taken with the role are associated with that user. After the source identity is set, the value cannot be changed. It is present in the request for all actions that are taken by the role and persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#id_roles_terms-and-concepts">chained role</a> sessions. You can configure your SAML identity provider to use an attribute associated with your users, like user name or email, as the source identity when calling <code>AssumeRoleWithSAML</code>. You do this by adding an attribute to the SAML assertion. For more information about using source identity, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html">Monitor and control actions taken with assumed roles</a> in the <i>IAM User Guide</i>.</p>
    /// <p>The regex used to validate this parameter is a string of characters consisting of upper- and lower-case alphanumeric characters with no spaces. You can also include underscores or any of the following characters: =,.@-</p>
    pub fn source_identity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_identity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value in the <code>SourceIdentity</code> attribute in the SAML assertion. The source identity value persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#iam-term-role-chaining">chained role</a> sessions.</p>
    /// <p>You can require users to set a source identity value when they assume a role. You do this by using the <code>sts:SourceIdentity</code> condition key in a role trust policy. That way, actions that are taken with the role are associated with that user. After the source identity is set, the value cannot be changed. It is present in the request for all actions that are taken by the role and persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#id_roles_terms-and-concepts">chained role</a> sessions. You can configure your SAML identity provider to use an attribute associated with your users, like user name or email, as the source identity when calling <code>AssumeRoleWithSAML</code>. You do this by adding an attribute to the SAML assertion. For more information about using source identity, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html">Monitor and control actions taken with assumed roles</a> in the <i>IAM User Guide</i>.</p>
    /// <p>The regex used to validate this parameter is a string of characters consisting of upper- and lower-case alphanumeric characters with no spaces. You can also include underscores or any of the following characters: =,.@-</p>
    pub fn set_source_identity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_identity = input;
        self
    }
    /// <p>The value in the <code>SourceIdentity</code> attribute in the SAML assertion. The source identity value persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#iam-term-role-chaining">chained role</a> sessions.</p>
    /// <p>You can require users to set a source identity value when they assume a role. You do this by using the <code>sts:SourceIdentity</code> condition key in a role trust policy. That way, actions that are taken with the role are associated with that user. After the source identity is set, the value cannot be changed. It is present in the request for all actions that are taken by the role and persists across <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#id_roles_terms-and-concepts">chained role</a> sessions. You can configure your SAML identity provider to use an attribute associated with your users, like user name or email, as the source identity when calling <code>AssumeRoleWithSAML</code>. You do this by adding an attribute to the SAML assertion. For more information about using source identity, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html">Monitor and control actions taken with assumed roles</a> in the <i>IAM User Guide</i>.</p>
    /// <p>The regex used to validate this parameter is a string of characters consisting of upper- and lower-case alphanumeric characters with no spaces. You can also include underscores or any of the following characters: =,.@-</p>
    pub fn get_source_identity(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_identity
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssumeRoleWithSamlOutput`](crate::operation::assume_role_with_saml::AssumeRoleWithSamlOutput).
    pub fn build(self) -> crate::operation::assume_role_with_saml::AssumeRoleWithSamlOutput {
        crate::operation::assume_role_with_saml::AssumeRoleWithSamlOutput {
            credentials: self.credentials,
            assumed_role_user: self.assumed_role_user,
            packed_policy_size: self.packed_policy_size,
            subject: self.subject,
            subject_type: self.subject_type,
            issuer: self.issuer,
            audience: self.audience,
            name_qualifier: self.name_qualifier,
            source_identity: self.source_identity,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for AssumeRoleWithSamlOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AssumeRoleWithSamlOutputBuilder");
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("assumed_role_user", &self.assumed_role_user);
        formatter.field("packed_policy_size", &self.packed_policy_size);
        formatter.field("subject", &self.subject);
        formatter.field("subject_type", &self.subject_type);
        formatter.field("issuer", &self.issuer);
        formatter.field("audience", &self.audience);
        formatter.field("name_qualifier", &self.name_qualifier);
        formatter.field("source_identity", &self.source_identity);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
