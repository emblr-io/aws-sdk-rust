// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchDescribeEntitiesOutput {
    /// <p>Details about each entity.</p>
    pub entity_details: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::EntityDetail>>,
    /// <p>A map of errors returned, with <code>EntityId</code> as the key and <code>errorDetail</code> as the value.</p>
    pub errors: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::BatchDescribeErrorDetail>>,
    _request_id: Option<String>,
}
impl BatchDescribeEntitiesOutput {
    /// <p>Details about each entity.</p>
    pub fn entity_details(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::EntityDetail>> {
        self.entity_details.as_ref()
    }
    /// <p>A map of errors returned, with <code>EntityId</code> as the key and <code>errorDetail</code> as the value.</p>
    pub fn errors(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::BatchDescribeErrorDetail>> {
        self.errors.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for BatchDescribeEntitiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchDescribeEntitiesOutput {
    /// Creates a new builder-style object to manufacture [`BatchDescribeEntitiesOutput`](crate::operation::batch_describe_entities::BatchDescribeEntitiesOutput).
    pub fn builder() -> crate::operation::batch_describe_entities::builders::BatchDescribeEntitiesOutputBuilder {
        crate::operation::batch_describe_entities::builders::BatchDescribeEntitiesOutputBuilder::default()
    }
}

/// A builder for [`BatchDescribeEntitiesOutput`](crate::operation::batch_describe_entities::BatchDescribeEntitiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchDescribeEntitiesOutputBuilder {
    pub(crate) entity_details: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::EntityDetail>>,
    pub(crate) errors: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::BatchDescribeErrorDetail>>,
    _request_id: Option<String>,
}
impl BatchDescribeEntitiesOutputBuilder {
    /// Adds a key-value pair to `entity_details`.
    ///
    /// To override the contents of this collection use [`set_entity_details`](Self::set_entity_details).
    ///
    /// <p>Details about each entity.</p>
    pub fn entity_details(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::EntityDetail) -> Self {
        let mut hash_map = self.entity_details.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.entity_details = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Details about each entity.</p>
    pub fn set_entity_details(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::EntityDetail>>,
    ) -> Self {
        self.entity_details = input;
        self
    }
    /// <p>Details about each entity.</p>
    pub fn get_entity_details(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::EntityDetail>> {
        &self.entity_details
    }
    /// Adds a key-value pair to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>A map of errors returned, with <code>EntityId</code> as the key and <code>errorDetail</code> as the value.</p>
    pub fn errors(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::BatchDescribeErrorDetail) -> Self {
        let mut hash_map = self.errors.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.errors = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of errors returned, with <code>EntityId</code> as the key and <code>errorDetail</code> as the value.</p>
    pub fn set_errors(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::BatchDescribeErrorDetail>>,
    ) -> Self {
        self.errors = input;
        self
    }
    /// <p>A map of errors returned, with <code>EntityId</code> as the key and <code>errorDetail</code> as the value.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::BatchDescribeErrorDetail>> {
        &self.errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchDescribeEntitiesOutput`](crate::operation::batch_describe_entities::BatchDescribeEntitiesOutput).
    pub fn build(self) -> crate::operation::batch_describe_entities::BatchDescribeEntitiesOutput {
        crate::operation::batch_describe_entities::BatchDescribeEntitiesOutput {
            entity_details: self.entity_details,
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
