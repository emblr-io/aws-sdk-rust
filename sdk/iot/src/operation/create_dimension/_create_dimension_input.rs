// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDimensionInput {
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the type of dimension. Supported types: <code>TOPIC_FILTER.</code></p>
    pub r#type: ::std::option::Option<crate::types::DimensionType>,
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub string_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Metadata that can be used to manage the dimension.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Each dimension must have a unique client request token. If you try to create a new dimension with the same token as a dimension that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateDimensionInput {
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Specifies the type of dimension. Supported types: <code>TOPIC_FILTER.</code></p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::DimensionType> {
        self.r#type.as_ref()
    }
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.string_values.is_none()`.
    pub fn string_values(&self) -> &[::std::string::String] {
        self.string_values.as_deref().unwrap_or_default()
    }
    /// <p>Metadata that can be used to manage the dimension.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Each dimension must have a unique client request token. If you try to create a new dimension with the same token as a dimension that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl CreateDimensionInput {
    /// Creates a new builder-style object to manufacture [`CreateDimensionInput`](crate::operation::create_dimension::CreateDimensionInput).
    pub fn builder() -> crate::operation::create_dimension::builders::CreateDimensionInputBuilder {
        crate::operation::create_dimension::builders::CreateDimensionInputBuilder::default()
    }
}

/// A builder for [`CreateDimensionInput`](crate::operation::create_dimension::CreateDimensionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDimensionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::DimensionType>,
    pub(crate) string_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateDimensionInputBuilder {
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Specifies the type of dimension. Supported types: <code>TOPIC_FILTER.</code></p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::DimensionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of dimension. Supported types: <code>TOPIC_FILTER.</code></p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DimensionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Specifies the type of dimension. Supported types: <code>TOPIC_FILTER.</code></p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DimensionType> {
        &self.r#type
    }
    /// Appends an item to `string_values`.
    ///
    /// To override the contents of this collection use [`set_string_values`](Self::set_string_values).
    ///
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub fn string_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.string_values.unwrap_or_default();
        v.push(input.into());
        self.string_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub fn set_string_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.string_values = input;
        self
    }
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub fn get_string_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.string_values
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata that can be used to manage the dimension.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata that can be used to manage the dimension.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata that can be used to manage the dimension.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Each dimension must have a unique client request token. If you try to create a new dimension with the same token as a dimension that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    /// This field is required.
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Each dimension must have a unique client request token. If you try to create a new dimension with the same token as a dimension that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Each dimension must have a unique client request token. If you try to create a new dimension with the same token as a dimension that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`CreateDimensionInput`](crate::operation::create_dimension::CreateDimensionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_dimension::CreateDimensionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_dimension::CreateDimensionInput {
            name: self.name,
            r#type: self.r#type,
            string_values: self.string_values,
            tags: self.tags,
            client_request_token: self.client_request_token,
        })
    }
}
