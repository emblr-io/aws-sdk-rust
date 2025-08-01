// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTypeInput {
    /// <p>The kind of extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub r#type: ::std::option::Option<crate::types::RegistryType>,
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub type_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of a specific version of the extension. The version ID is the value at the end of the Amazon Resource Name (ARN) assigned to the extension version when it is registered.</p>
    /// <p>If you specify a <code>VersionId</code>, <code>DescribeType</code> returns information about that specific extension version. Otherwise, it returns information about the default extension version.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>The publisher ID of the extension publisher.</p>
    /// <p>Extensions provided by Amazon Web Services are not assigned a publisher ID.</p>
    pub publisher_id: ::std::option::Option<::std::string::String>,
    /// <p>The version number of a public third-party extension.</p>
    pub public_version_number: ::std::option::Option<::std::string::String>,
}
impl DescribeTypeInput {
    /// <p>The kind of extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::RegistryType> {
        self.r#type.as_ref()
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn type_name(&self) -> ::std::option::Option<&str> {
        self.type_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ID of a specific version of the extension. The version ID is the value at the end of the Amazon Resource Name (ARN) assigned to the extension version when it is registered.</p>
    /// <p>If you specify a <code>VersionId</code>, <code>DescribeType</code> returns information about that specific extension version. Otherwise, it returns information about the default extension version.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>The publisher ID of the extension publisher.</p>
    /// <p>Extensions provided by Amazon Web Services are not assigned a publisher ID.</p>
    pub fn publisher_id(&self) -> ::std::option::Option<&str> {
        self.publisher_id.as_deref()
    }
    /// <p>The version number of a public third-party extension.</p>
    pub fn public_version_number(&self) -> ::std::option::Option<&str> {
        self.public_version_number.as_deref()
    }
}
impl DescribeTypeInput {
    /// Creates a new builder-style object to manufacture [`DescribeTypeInput`](crate::operation::describe_type::DescribeTypeInput).
    pub fn builder() -> crate::operation::describe_type::builders::DescribeTypeInputBuilder {
        crate::operation::describe_type::builders::DescribeTypeInputBuilder::default()
    }
}

/// A builder for [`DescribeTypeInput`](crate::operation::describe_type::DescribeTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTypeInputBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::RegistryType>,
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) publisher_id: ::std::option::Option<::std::string::String>,
    pub(crate) public_version_number: ::std::option::Option<::std::string::String>,
}
impl DescribeTypeInputBuilder {
    /// <p>The kind of extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn r#type(mut self, input: crate::types::RegistryType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The kind of extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RegistryType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The kind of extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RegistryType> {
        &self.r#type
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    /// <p>Conditional: You must specify either <code>TypeName</code> and <code>Type</code>, or <code>Arn</code>.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID of a specific version of the extension. The version ID is the value at the end of the Amazon Resource Name (ARN) assigned to the extension version when it is registered.</p>
    /// <p>If you specify a <code>VersionId</code>, <code>DescribeType</code> returns information about that specific extension version. Otherwise, it returns information about the default extension version.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of a specific version of the extension. The version ID is the value at the end of the Amazon Resource Name (ARN) assigned to the extension version when it is registered.</p>
    /// <p>If you specify a <code>VersionId</code>, <code>DescribeType</code> returns information about that specific extension version. Otherwise, it returns information about the default extension version.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The ID of a specific version of the extension. The version ID is the value at the end of the Amazon Resource Name (ARN) assigned to the extension version when it is registered.</p>
    /// <p>If you specify a <code>VersionId</code>, <code>DescribeType</code> returns information about that specific extension version. Otherwise, it returns information about the default extension version.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// <p>The publisher ID of the extension publisher.</p>
    /// <p>Extensions provided by Amazon Web Services are not assigned a publisher ID.</p>
    pub fn publisher_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.publisher_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The publisher ID of the extension publisher.</p>
    /// <p>Extensions provided by Amazon Web Services are not assigned a publisher ID.</p>
    pub fn set_publisher_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.publisher_id = input;
        self
    }
    /// <p>The publisher ID of the extension publisher.</p>
    /// <p>Extensions provided by Amazon Web Services are not assigned a publisher ID.</p>
    pub fn get_publisher_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.publisher_id
    }
    /// <p>The version number of a public third-party extension.</p>
    pub fn public_version_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_version_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version number of a public third-party extension.</p>
    pub fn set_public_version_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_version_number = input;
        self
    }
    /// <p>The version number of a public third-party extension.</p>
    pub fn get_public_version_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_version_number
    }
    /// Consumes the builder and constructs a [`DescribeTypeInput`](crate::operation::describe_type::DescribeTypeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_type::DescribeTypeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_type::DescribeTypeInput {
            r#type: self.r#type,
            type_name: self.type_name,
            arn: self.arn,
            version_id: self.version_id,
            publisher_id: self.publisher_id,
            public_version_number: self.public_version_number,
        })
    }
}
