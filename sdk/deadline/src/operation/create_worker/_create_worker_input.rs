// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWorkerInput {
    /// <p>The farm ID of the farm to connect to the worker.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The fleet ID to connect to the worker.</p>
    pub fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>The IP address and host name of the worker.</p>
    pub host_properties: ::std::option::Option<crate::types::HostPropertiesRequest>,
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Each tag consists of a tag key and a tag value. Tag keys and values are both required, but tag values can be empty strings.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateWorkerInput {
    /// <p>The farm ID of the farm to connect to the worker.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The fleet ID to connect to the worker.</p>
    pub fn fleet_id(&self) -> ::std::option::Option<&str> {
        self.fleet_id.as_deref()
    }
    /// <p>The IP address and host name of the worker.</p>
    pub fn host_properties(&self) -> ::std::option::Option<&crate::types::HostPropertiesRequest> {
        self.host_properties.as_ref()
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Each tag consists of a tag key and a tag value. Tag keys and values are both required, but tag values can be empty strings.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateWorkerInput {
    /// Creates a new builder-style object to manufacture [`CreateWorkerInput`](crate::operation::create_worker::CreateWorkerInput).
    pub fn builder() -> crate::operation::create_worker::builders::CreateWorkerInputBuilder {
        crate::operation::create_worker::builders::CreateWorkerInputBuilder::default()
    }
}

/// A builder for [`CreateWorkerInput`](crate::operation::create_worker::CreateWorkerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWorkerInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) host_properties: ::std::option::Option<crate::types::HostPropertiesRequest>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateWorkerInputBuilder {
    /// <p>The farm ID of the farm to connect to the worker.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The farm ID of the farm to connect to the worker.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The farm ID of the farm to connect to the worker.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The fleet ID to connect to the worker.</p>
    /// This field is required.
    pub fn fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fleet ID to connect to the worker.</p>
    pub fn set_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_id = input;
        self
    }
    /// <p>The fleet ID to connect to the worker.</p>
    pub fn get_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_id
    }
    /// <p>The IP address and host name of the worker.</p>
    pub fn host_properties(mut self, input: crate::types::HostPropertiesRequest) -> Self {
        self.host_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The IP address and host name of the worker.</p>
    pub fn set_host_properties(mut self, input: ::std::option::Option<crate::types::HostPropertiesRequest>) -> Self {
        self.host_properties = input;
        self
    }
    /// <p>The IP address and host name of the worker.</p>
    pub fn get_host_properties(&self) -> &::std::option::Option<crate::types::HostPropertiesRequest> {
        &self.host_properties
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Each tag consists of a tag key and a tag value. Tag keys and values are both required, but tag values can be empty strings.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Each tag consists of a tag key and a tag value. Tag keys and values are both required, but tag values can be empty strings.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Each tag consists of a tag key and a tag value. Tag keys and values are both required, but tag values can be empty strings.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateWorkerInput`](crate::operation::create_worker::CreateWorkerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_worker::CreateWorkerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_worker::CreateWorkerInput {
            farm_id: self.farm_id,
            fleet_id: self.fleet_id,
            host_properties: self.host_properties,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
