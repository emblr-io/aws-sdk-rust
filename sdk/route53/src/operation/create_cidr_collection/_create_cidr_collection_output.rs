// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCidrCollectionOutput {
    /// <p>A complex type that contains information about the CIDR collection.</p>
    pub collection: ::std::option::Option<crate::types::CidrCollection>,
    /// <p>A unique URL that represents the location for the CIDR collection.</p>
    pub location: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCidrCollectionOutput {
    /// <p>A complex type that contains information about the CIDR collection.</p>
    pub fn collection(&self) -> ::std::option::Option<&crate::types::CidrCollection> {
        self.collection.as_ref()
    }
    /// <p>A unique URL that represents the location for the CIDR collection.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCidrCollectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCidrCollectionOutput {
    /// Creates a new builder-style object to manufacture [`CreateCidrCollectionOutput`](crate::operation::create_cidr_collection::CreateCidrCollectionOutput).
    pub fn builder() -> crate::operation::create_cidr_collection::builders::CreateCidrCollectionOutputBuilder {
        crate::operation::create_cidr_collection::builders::CreateCidrCollectionOutputBuilder::default()
    }
}

/// A builder for [`CreateCidrCollectionOutput`](crate::operation::create_cidr_collection::CreateCidrCollectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCidrCollectionOutputBuilder {
    pub(crate) collection: ::std::option::Option<crate::types::CidrCollection>,
    pub(crate) location: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCidrCollectionOutputBuilder {
    /// <p>A complex type that contains information about the CIDR collection.</p>
    pub fn collection(mut self, input: crate::types::CidrCollection) -> Self {
        self.collection = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that contains information about the CIDR collection.</p>
    pub fn set_collection(mut self, input: ::std::option::Option<crate::types::CidrCollection>) -> Self {
        self.collection = input;
        self
    }
    /// <p>A complex type that contains information about the CIDR collection.</p>
    pub fn get_collection(&self) -> &::std::option::Option<crate::types::CidrCollection> {
        &self.collection
    }
    /// <p>A unique URL that represents the location for the CIDR collection.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique URL that represents the location for the CIDR collection.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>A unique URL that represents the location for the CIDR collection.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCidrCollectionOutput`](crate::operation::create_cidr_collection::CreateCidrCollectionOutput).
    pub fn build(self) -> crate::operation::create_cidr_collection::CreateCidrCollectionOutput {
        crate::operation::create_cidr_collection::CreateCidrCollectionOutput {
            collection: self.collection,
            location: self.location,
            _request_id: self._request_id,
        }
    }
}
