// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct StartSourceNetworkRecoveryInput {
    /// <p>The Source Networks that we want to start a Recovery Job for.</p>
    pub source_networks: ::std::option::Option<::std::vec::Vec<crate::types::StartSourceNetworkRecoveryRequestNetworkEntry>>,
    /// <p>Don't update existing CloudFormation Stack, recover the network using a new stack.</p>
    pub deploy_as_new: ::std::option::Option<bool>,
    /// <p>The tags to be associated with the Source Network recovery Job.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl StartSourceNetworkRecoveryInput {
    /// <p>The Source Networks that we want to start a Recovery Job for.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.source_networks.is_none()`.
    pub fn source_networks(&self) -> &[crate::types::StartSourceNetworkRecoveryRequestNetworkEntry] {
        self.source_networks.as_deref().unwrap_or_default()
    }
    /// <p>Don't update existing CloudFormation Stack, recover the network using a new stack.</p>
    pub fn deploy_as_new(&self) -> ::std::option::Option<bool> {
        self.deploy_as_new
    }
    /// <p>The tags to be associated with the Source Network recovery Job.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for StartSourceNetworkRecoveryInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartSourceNetworkRecoveryInput");
        formatter.field("source_networks", &self.source_networks);
        formatter.field("deploy_as_new", &self.deploy_as_new);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl StartSourceNetworkRecoveryInput {
    /// Creates a new builder-style object to manufacture [`StartSourceNetworkRecoveryInput`](crate::operation::start_source_network_recovery::StartSourceNetworkRecoveryInput).
    pub fn builder() -> crate::operation::start_source_network_recovery::builders::StartSourceNetworkRecoveryInputBuilder {
        crate::operation::start_source_network_recovery::builders::StartSourceNetworkRecoveryInputBuilder::default()
    }
}

/// A builder for [`StartSourceNetworkRecoveryInput`](crate::operation::start_source_network_recovery::StartSourceNetworkRecoveryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct StartSourceNetworkRecoveryInputBuilder {
    pub(crate) source_networks: ::std::option::Option<::std::vec::Vec<crate::types::StartSourceNetworkRecoveryRequestNetworkEntry>>,
    pub(crate) deploy_as_new: ::std::option::Option<bool>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl StartSourceNetworkRecoveryInputBuilder {
    /// Appends an item to `source_networks`.
    ///
    /// To override the contents of this collection use [`set_source_networks`](Self::set_source_networks).
    ///
    /// <p>The Source Networks that we want to start a Recovery Job for.</p>
    pub fn source_networks(mut self, input: crate::types::StartSourceNetworkRecoveryRequestNetworkEntry) -> Self {
        let mut v = self.source_networks.unwrap_or_default();
        v.push(input);
        self.source_networks = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Source Networks that we want to start a Recovery Job for.</p>
    pub fn set_source_networks(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::StartSourceNetworkRecoveryRequestNetworkEntry>>,
    ) -> Self {
        self.source_networks = input;
        self
    }
    /// <p>The Source Networks that we want to start a Recovery Job for.</p>
    pub fn get_source_networks(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StartSourceNetworkRecoveryRequestNetworkEntry>> {
        &self.source_networks
    }
    /// <p>Don't update existing CloudFormation Stack, recover the network using a new stack.</p>
    pub fn deploy_as_new(mut self, input: bool) -> Self {
        self.deploy_as_new = ::std::option::Option::Some(input);
        self
    }
    /// <p>Don't update existing CloudFormation Stack, recover the network using a new stack.</p>
    pub fn set_deploy_as_new(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deploy_as_new = input;
        self
    }
    /// <p>Don't update existing CloudFormation Stack, recover the network using a new stack.</p>
    pub fn get_deploy_as_new(&self) -> &::std::option::Option<bool> {
        &self.deploy_as_new
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to be associated with the Source Network recovery Job.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to be associated with the Source Network recovery Job.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to be associated with the Source Network recovery Job.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`StartSourceNetworkRecoveryInput`](crate::operation::start_source_network_recovery::StartSourceNetworkRecoveryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_source_network_recovery::StartSourceNetworkRecoveryInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_source_network_recovery::StartSourceNetworkRecoveryInput {
            source_networks: self.source_networks,
            deploy_as_new: self.deploy_as_new,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for StartSourceNetworkRecoveryInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartSourceNetworkRecoveryInputBuilder");
        formatter.field("source_networks", &self.source_networks);
        formatter.field("deploy_as_new", &self.deploy_as_new);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
