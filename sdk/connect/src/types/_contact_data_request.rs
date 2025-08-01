// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request object with information to create a contact.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContactDataRequest {
    /// <p>Endpoint associated with the Amazon Connect instance from which outbound contact will be initiated for the campaign.</p>
    pub system_endpoint: ::std::option::Option<crate::types::Endpoint>,
    /// <p>Endpoint of the customer for which contact will be initiated.</p>
    pub customer_endpoint: ::std::option::Option<crate::types::Endpoint>,
    /// <p>Identifier to uniquely identify individual requests in the batch.</p>
    pub request_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the queue associated with the Amazon Connect instance in which contacts that are created will be queued.</p>
    pub queue_id: ::std::option::Option<::std::string::String>,
    /// <p>List of attributes to be stored in a contact.</p>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Structure to store information associated with a campaign.</p>
    pub campaign: ::std::option::Option<crate::types::Campaign>,
}
impl ContactDataRequest {
    /// <p>Endpoint associated with the Amazon Connect instance from which outbound contact will be initiated for the campaign.</p>
    pub fn system_endpoint(&self) -> ::std::option::Option<&crate::types::Endpoint> {
        self.system_endpoint.as_ref()
    }
    /// <p>Endpoint of the customer for which contact will be initiated.</p>
    pub fn customer_endpoint(&self) -> ::std::option::Option<&crate::types::Endpoint> {
        self.customer_endpoint.as_ref()
    }
    /// <p>Identifier to uniquely identify individual requests in the batch.</p>
    pub fn request_identifier(&self) -> ::std::option::Option<&str> {
        self.request_identifier.as_deref()
    }
    /// <p>The identifier of the queue associated with the Amazon Connect instance in which contacts that are created will be queued.</p>
    pub fn queue_id(&self) -> ::std::option::Option<&str> {
        self.queue_id.as_deref()
    }
    /// <p>List of attributes to be stored in a contact.</p>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.attributes.as_ref()
    }
    /// <p>Structure to store information associated with a campaign.</p>
    pub fn campaign(&self) -> ::std::option::Option<&crate::types::Campaign> {
        self.campaign.as_ref()
    }
}
impl ContactDataRequest {
    /// Creates a new builder-style object to manufacture [`ContactDataRequest`](crate::types::ContactDataRequest).
    pub fn builder() -> crate::types::builders::ContactDataRequestBuilder {
        crate::types::builders::ContactDataRequestBuilder::default()
    }
}

/// A builder for [`ContactDataRequest`](crate::types::ContactDataRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContactDataRequestBuilder {
    pub(crate) system_endpoint: ::std::option::Option<crate::types::Endpoint>,
    pub(crate) customer_endpoint: ::std::option::Option<crate::types::Endpoint>,
    pub(crate) request_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) campaign: ::std::option::Option<crate::types::Campaign>,
}
impl ContactDataRequestBuilder {
    /// <p>Endpoint associated with the Amazon Connect instance from which outbound contact will be initiated for the campaign.</p>
    pub fn system_endpoint(mut self, input: crate::types::Endpoint) -> Self {
        self.system_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Endpoint associated with the Amazon Connect instance from which outbound contact will be initiated for the campaign.</p>
    pub fn set_system_endpoint(mut self, input: ::std::option::Option<crate::types::Endpoint>) -> Self {
        self.system_endpoint = input;
        self
    }
    /// <p>Endpoint associated with the Amazon Connect instance from which outbound contact will be initiated for the campaign.</p>
    pub fn get_system_endpoint(&self) -> &::std::option::Option<crate::types::Endpoint> {
        &self.system_endpoint
    }
    /// <p>Endpoint of the customer for which contact will be initiated.</p>
    pub fn customer_endpoint(mut self, input: crate::types::Endpoint) -> Self {
        self.customer_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Endpoint of the customer for which contact will be initiated.</p>
    pub fn set_customer_endpoint(mut self, input: ::std::option::Option<crate::types::Endpoint>) -> Self {
        self.customer_endpoint = input;
        self
    }
    /// <p>Endpoint of the customer for which contact will be initiated.</p>
    pub fn get_customer_endpoint(&self) -> &::std::option::Option<crate::types::Endpoint> {
        &self.customer_endpoint
    }
    /// <p>Identifier to uniquely identify individual requests in the batch.</p>
    pub fn request_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier to uniquely identify individual requests in the batch.</p>
    pub fn set_request_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_identifier = input;
        self
    }
    /// <p>Identifier to uniquely identify individual requests in the batch.</p>
    pub fn get_request_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_identifier
    }
    /// <p>The identifier of the queue associated with the Amazon Connect instance in which contacts that are created will be queued.</p>
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the queue associated with the Amazon Connect instance in which contacts that are created will be queued.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The identifier of the queue associated with the Amazon Connect instance in which contacts that are created will be queued.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>List of attributes to be stored in a contact.</p>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>List of attributes to be stored in a contact.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>List of attributes to be stored in a contact.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.attributes
    }
    /// <p>Structure to store information associated with a campaign.</p>
    pub fn campaign(mut self, input: crate::types::Campaign) -> Self {
        self.campaign = ::std::option::Option::Some(input);
        self
    }
    /// <p>Structure to store information associated with a campaign.</p>
    pub fn set_campaign(mut self, input: ::std::option::Option<crate::types::Campaign>) -> Self {
        self.campaign = input;
        self
    }
    /// <p>Structure to store information associated with a campaign.</p>
    pub fn get_campaign(&self) -> &::std::option::Option<crate::types::Campaign> {
        &self.campaign
    }
    /// Consumes the builder and constructs a [`ContactDataRequest`](crate::types::ContactDataRequest).
    pub fn build(self) -> crate::types::ContactDataRequest {
        crate::types::ContactDataRequest {
            system_endpoint: self.system_endpoint,
            customer_endpoint: self.customer_endpoint,
            request_identifier: self.request_identifier,
            queue_id: self.queue_id,
            attributes: self.attributes,
            campaign: self.campaign,
        }
    }
}
