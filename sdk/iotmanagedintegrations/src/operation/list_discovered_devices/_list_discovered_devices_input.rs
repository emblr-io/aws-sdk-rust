// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDiscoveredDevicesInput {
    /// <p>The identifier of the device discovery job to list discovered devices for.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>A token used for pagination of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of discovered devices to return in a single response.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListDiscoveredDevicesInput {
    /// <p>The identifier of the device discovery job to list discovered devices for.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>A token used for pagination of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of discovered devices to return in a single response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListDiscoveredDevicesInput {
    /// Creates a new builder-style object to manufacture [`ListDiscoveredDevicesInput`](crate::operation::list_discovered_devices::ListDiscoveredDevicesInput).
    pub fn builder() -> crate::operation::list_discovered_devices::builders::ListDiscoveredDevicesInputBuilder {
        crate::operation::list_discovered_devices::builders::ListDiscoveredDevicesInputBuilder::default()
    }
}

/// A builder for [`ListDiscoveredDevicesInput`](crate::operation::list_discovered_devices::ListDiscoveredDevicesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDiscoveredDevicesInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListDiscoveredDevicesInputBuilder {
    /// <p>The identifier of the device discovery job to list discovered devices for.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the device discovery job to list discovered devices for.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the device discovery job to list discovered devices for.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>A token used for pagination of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token used for pagination of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token used for pagination of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of discovered devices to return in a single response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of discovered devices to return in a single response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of discovered devices to return in a single response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListDiscoveredDevicesInput`](crate::operation::list_discovered_devices::ListDiscoveredDevicesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_discovered_devices::ListDiscoveredDevicesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_discovered_devices::ListDiscoveredDevicesInput {
            identifier: self.identifier,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
