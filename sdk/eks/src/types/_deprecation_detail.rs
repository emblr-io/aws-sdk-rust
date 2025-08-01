// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary information about deprecated resource usage for an insight check in the <code>UPGRADE_READINESS</code> category.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeprecationDetail {
    /// <p>The deprecated version of the resource.</p>
    pub usage: ::std::option::Option<::std::string::String>,
    /// <p>The newer version of the resource to migrate to if applicable.</p>
    pub replaced_with: ::std::option::Option<::std::string::String>,
    /// <p>The version of the software where the deprecated resource version will stop being served.</p>
    pub stop_serving_version: ::std::option::Option<::std::string::String>,
    /// <p>The version of the software where the newer resource version became available to migrate to if applicable.</p>
    pub start_serving_replacement_version: ::std::option::Option<::std::string::String>,
    /// <p>Details about Kubernetes clients using the deprecated resources.</p>
    pub client_stats: ::std::option::Option<::std::vec::Vec<crate::types::ClientStat>>,
}
impl DeprecationDetail {
    /// <p>The deprecated version of the resource.</p>
    pub fn usage(&self) -> ::std::option::Option<&str> {
        self.usage.as_deref()
    }
    /// <p>The newer version of the resource to migrate to if applicable.</p>
    pub fn replaced_with(&self) -> ::std::option::Option<&str> {
        self.replaced_with.as_deref()
    }
    /// <p>The version of the software where the deprecated resource version will stop being served.</p>
    pub fn stop_serving_version(&self) -> ::std::option::Option<&str> {
        self.stop_serving_version.as_deref()
    }
    /// <p>The version of the software where the newer resource version became available to migrate to if applicable.</p>
    pub fn start_serving_replacement_version(&self) -> ::std::option::Option<&str> {
        self.start_serving_replacement_version.as_deref()
    }
    /// <p>Details about Kubernetes clients using the deprecated resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.client_stats.is_none()`.
    pub fn client_stats(&self) -> &[crate::types::ClientStat] {
        self.client_stats.as_deref().unwrap_or_default()
    }
}
impl DeprecationDetail {
    /// Creates a new builder-style object to manufacture [`DeprecationDetail`](crate::types::DeprecationDetail).
    pub fn builder() -> crate::types::builders::DeprecationDetailBuilder {
        crate::types::builders::DeprecationDetailBuilder::default()
    }
}

/// A builder for [`DeprecationDetail`](crate::types::DeprecationDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeprecationDetailBuilder {
    pub(crate) usage: ::std::option::Option<::std::string::String>,
    pub(crate) replaced_with: ::std::option::Option<::std::string::String>,
    pub(crate) stop_serving_version: ::std::option::Option<::std::string::String>,
    pub(crate) start_serving_replacement_version: ::std::option::Option<::std::string::String>,
    pub(crate) client_stats: ::std::option::Option<::std::vec::Vec<crate::types::ClientStat>>,
}
impl DeprecationDetailBuilder {
    /// <p>The deprecated version of the resource.</p>
    pub fn usage(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The deprecated version of the resource.</p>
    pub fn set_usage(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage = input;
        self
    }
    /// <p>The deprecated version of the resource.</p>
    pub fn get_usage(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage
    }
    /// <p>The newer version of the resource to migrate to if applicable.</p>
    pub fn replaced_with(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replaced_with = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The newer version of the resource to migrate to if applicable.</p>
    pub fn set_replaced_with(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replaced_with = input;
        self
    }
    /// <p>The newer version of the resource to migrate to if applicable.</p>
    pub fn get_replaced_with(&self) -> &::std::option::Option<::std::string::String> {
        &self.replaced_with
    }
    /// <p>The version of the software where the deprecated resource version will stop being served.</p>
    pub fn stop_serving_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stop_serving_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the software where the deprecated resource version will stop being served.</p>
    pub fn set_stop_serving_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stop_serving_version = input;
        self
    }
    /// <p>The version of the software where the deprecated resource version will stop being served.</p>
    pub fn get_stop_serving_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.stop_serving_version
    }
    /// <p>The version of the software where the newer resource version became available to migrate to if applicable.</p>
    pub fn start_serving_replacement_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_serving_replacement_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the software where the newer resource version became available to migrate to if applicable.</p>
    pub fn set_start_serving_replacement_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_serving_replacement_version = input;
        self
    }
    /// <p>The version of the software where the newer resource version became available to migrate to if applicable.</p>
    pub fn get_start_serving_replacement_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_serving_replacement_version
    }
    /// Appends an item to `client_stats`.
    ///
    /// To override the contents of this collection use [`set_client_stats`](Self::set_client_stats).
    ///
    /// <p>Details about Kubernetes clients using the deprecated resources.</p>
    pub fn client_stats(mut self, input: crate::types::ClientStat) -> Self {
        let mut v = self.client_stats.unwrap_or_default();
        v.push(input);
        self.client_stats = ::std::option::Option::Some(v);
        self
    }
    /// <p>Details about Kubernetes clients using the deprecated resources.</p>
    pub fn set_client_stats(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ClientStat>>) -> Self {
        self.client_stats = input;
        self
    }
    /// <p>Details about Kubernetes clients using the deprecated resources.</p>
    pub fn get_client_stats(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ClientStat>> {
        &self.client_stats
    }
    /// Consumes the builder and constructs a [`DeprecationDetail`](crate::types::DeprecationDetail).
    pub fn build(self) -> crate::types::DeprecationDetail {
        crate::types::DeprecationDetail {
            usage: self.usage,
            replaced_with: self.replaced_with,
            stop_serving_version: self.stop_serving_version,
            start_serving_replacement_version: self.start_serving_replacement_version,
            client_stats: self.client_stats,
        }
    }
}
