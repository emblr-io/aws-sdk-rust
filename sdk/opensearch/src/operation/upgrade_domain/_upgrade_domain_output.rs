// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the response returned by <code>UpgradeDomain</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpgradeDomainOutput {
    /// <p>The unique identifier of the domain upgrade.</p>
    pub upgrade_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the domain that was upgraded.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>OpenSearch or Elasticsearch version that the domain was upgraded to.</p>
    pub target_version: ::std::option::Option<::std::string::String>,
    /// <p>When true, indicates that an upgrade eligibility check was performed.</p>
    pub perform_check_only: ::std::option::Option<bool>,
    /// <p>The advanced options configuration for the domain.</p>
    pub advanced_options: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Container for information about a configuration change happening on a domain.</p>
    pub change_progress_details: ::std::option::Option<crate::types::ChangeProgressDetails>,
    _request_id: Option<String>,
}
impl UpgradeDomainOutput {
    /// <p>The unique identifier of the domain upgrade.</p>
    pub fn upgrade_id(&self) -> ::std::option::Option<&str> {
        self.upgrade_id.as_deref()
    }
    /// <p>The name of the domain that was upgraded.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>OpenSearch or Elasticsearch version that the domain was upgraded to.</p>
    pub fn target_version(&self) -> ::std::option::Option<&str> {
        self.target_version.as_deref()
    }
    /// <p>When true, indicates that an upgrade eligibility check was performed.</p>
    pub fn perform_check_only(&self) -> ::std::option::Option<bool> {
        self.perform_check_only
    }
    /// <p>The advanced options configuration for the domain.</p>
    pub fn advanced_options(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.advanced_options.as_ref()
    }
    /// <p>Container for information about a configuration change happening on a domain.</p>
    pub fn change_progress_details(&self) -> ::std::option::Option<&crate::types::ChangeProgressDetails> {
        self.change_progress_details.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpgradeDomainOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpgradeDomainOutput {
    /// Creates a new builder-style object to manufacture [`UpgradeDomainOutput`](crate::operation::upgrade_domain::UpgradeDomainOutput).
    pub fn builder() -> crate::operation::upgrade_domain::builders::UpgradeDomainOutputBuilder {
        crate::operation::upgrade_domain::builders::UpgradeDomainOutputBuilder::default()
    }
}

/// A builder for [`UpgradeDomainOutput`](crate::operation::upgrade_domain::UpgradeDomainOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpgradeDomainOutputBuilder {
    pub(crate) upgrade_id: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_version: ::std::option::Option<::std::string::String>,
    pub(crate) perform_check_only: ::std::option::Option<bool>,
    pub(crate) advanced_options: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) change_progress_details: ::std::option::Option<crate::types::ChangeProgressDetails>,
    _request_id: Option<String>,
}
impl UpgradeDomainOutputBuilder {
    /// <p>The unique identifier of the domain upgrade.</p>
    pub fn upgrade_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.upgrade_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the domain upgrade.</p>
    pub fn set_upgrade_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.upgrade_id = input;
        self
    }
    /// <p>The unique identifier of the domain upgrade.</p>
    pub fn get_upgrade_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.upgrade_id
    }
    /// <p>The name of the domain that was upgraded.</p>
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain that was upgraded.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the domain that was upgraded.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>OpenSearch or Elasticsearch version that the domain was upgraded to.</p>
    pub fn target_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>OpenSearch or Elasticsearch version that the domain was upgraded to.</p>
    pub fn set_target_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_version = input;
        self
    }
    /// <p>OpenSearch or Elasticsearch version that the domain was upgraded to.</p>
    pub fn get_target_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_version
    }
    /// <p>When true, indicates that an upgrade eligibility check was performed.</p>
    pub fn perform_check_only(mut self, input: bool) -> Self {
        self.perform_check_only = ::std::option::Option::Some(input);
        self
    }
    /// <p>When true, indicates that an upgrade eligibility check was performed.</p>
    pub fn set_perform_check_only(mut self, input: ::std::option::Option<bool>) -> Self {
        self.perform_check_only = input;
        self
    }
    /// <p>When true, indicates that an upgrade eligibility check was performed.</p>
    pub fn get_perform_check_only(&self) -> &::std::option::Option<bool> {
        &self.perform_check_only
    }
    /// Adds a key-value pair to `advanced_options`.
    ///
    /// To override the contents of this collection use [`set_advanced_options`](Self::set_advanced_options).
    ///
    /// <p>The advanced options configuration for the domain.</p>
    pub fn advanced_options(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.advanced_options.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.advanced_options = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The advanced options configuration for the domain.</p>
    pub fn set_advanced_options(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.advanced_options = input;
        self
    }
    /// <p>The advanced options configuration for the domain.</p>
    pub fn get_advanced_options(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.advanced_options
    }
    /// <p>Container for information about a configuration change happening on a domain.</p>
    pub fn change_progress_details(mut self, input: crate::types::ChangeProgressDetails) -> Self {
        self.change_progress_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Container for information about a configuration change happening on a domain.</p>
    pub fn set_change_progress_details(mut self, input: ::std::option::Option<crate::types::ChangeProgressDetails>) -> Self {
        self.change_progress_details = input;
        self
    }
    /// <p>Container for information about a configuration change happening on a domain.</p>
    pub fn get_change_progress_details(&self) -> &::std::option::Option<crate::types::ChangeProgressDetails> {
        &self.change_progress_details
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpgradeDomainOutput`](crate::operation::upgrade_domain::UpgradeDomainOutput).
    pub fn build(self) -> crate::operation::upgrade_domain::UpgradeDomainOutput {
        crate::operation::upgrade_domain::UpgradeDomainOutput {
            upgrade_id: self.upgrade_id,
            domain_name: self.domain_name,
            target_version: self.target_version,
            perform_check_only: self.perform_check_only,
            advanced_options: self.advanced_options,
            change_progress_details: self.change_progress_details,
            _request_id: self._request_id,
        }
    }
}
