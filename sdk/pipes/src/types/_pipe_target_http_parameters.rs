// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>These are custom parameter to be used when the target is an API Gateway REST APIs or EventBridge ApiDestinations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PipeTargetHttpParameters {
    /// <p>The path parameter values to be used to populate API Gateway REST API or EventBridge ApiDestination path wildcards ("*").</p>
    pub path_parameter_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The headers that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub header_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The query string keys/values that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub query_string_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PipeTargetHttpParameters {
    /// <p>The path parameter values to be used to populate API Gateway REST API or EventBridge ApiDestination path wildcards ("*").</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.path_parameter_values.is_none()`.
    pub fn path_parameter_values(&self) -> &[::std::string::String] {
        self.path_parameter_values.as_deref().unwrap_or_default()
    }
    /// <p>The headers that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn header_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.header_parameters.as_ref()
    }
    /// <p>The query string keys/values that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn query_string_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.query_string_parameters.as_ref()
    }
}
impl PipeTargetHttpParameters {
    /// Creates a new builder-style object to manufacture [`PipeTargetHttpParameters`](crate::types::PipeTargetHttpParameters).
    pub fn builder() -> crate::types::builders::PipeTargetHttpParametersBuilder {
        crate::types::builders::PipeTargetHttpParametersBuilder::default()
    }
}

/// A builder for [`PipeTargetHttpParameters`](crate::types::PipeTargetHttpParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PipeTargetHttpParametersBuilder {
    pub(crate) path_parameter_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) header_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) query_string_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PipeTargetHttpParametersBuilder {
    /// Appends an item to `path_parameter_values`.
    ///
    /// To override the contents of this collection use [`set_path_parameter_values`](Self::set_path_parameter_values).
    ///
    /// <p>The path parameter values to be used to populate API Gateway REST API or EventBridge ApiDestination path wildcards ("*").</p>
    pub fn path_parameter_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.path_parameter_values.unwrap_or_default();
        v.push(input.into());
        self.path_parameter_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The path parameter values to be used to populate API Gateway REST API or EventBridge ApiDestination path wildcards ("*").</p>
    pub fn set_path_parameter_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.path_parameter_values = input;
        self
    }
    /// <p>The path parameter values to be used to populate API Gateway REST API or EventBridge ApiDestination path wildcards ("*").</p>
    pub fn get_path_parameter_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.path_parameter_values
    }
    /// Adds a key-value pair to `header_parameters`.
    ///
    /// To override the contents of this collection use [`set_header_parameters`](Self::set_header_parameters).
    ///
    /// <p>The headers that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn header_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.header_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.header_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The headers that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn set_header_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.header_parameters = input;
        self
    }
    /// <p>The headers that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn get_header_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.header_parameters
    }
    /// Adds a key-value pair to `query_string_parameters`.
    ///
    /// To override the contents of this collection use [`set_query_string_parameters`](Self::set_query_string_parameters).
    ///
    /// <p>The query string keys/values that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn query_string_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.query_string_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.query_string_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The query string keys/values that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn set_query_string_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.query_string_parameters = input;
        self
    }
    /// <p>The query string keys/values that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.</p>
    pub fn get_query_string_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.query_string_parameters
    }
    /// Consumes the builder and constructs a [`PipeTargetHttpParameters`](crate::types::PipeTargetHttpParameters).
    pub fn build(self) -> crate::types::PipeTargetHttpParameters {
        crate::types::PipeTargetHttpParameters {
            path_parameter_values: self.path_parameter_values,
            header_parameters: self.header_parameters,
            query_string_parameters: self.query_string_parameters,
        }
    }
}
