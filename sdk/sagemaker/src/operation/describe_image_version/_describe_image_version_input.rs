// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeImageVersionInput {
    /// <p>The name of the image.</p>
    pub image_name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the image. If not specified, the latest version is described.</p>
    pub version: ::std::option::Option<i32>,
    /// <p>The alias of the image version.</p>
    pub alias: ::std::option::Option<::std::string::String>,
}
impl DescribeImageVersionInput {
    /// <p>The name of the image.</p>
    pub fn image_name(&self) -> ::std::option::Option<&str> {
        self.image_name.as_deref()
    }
    /// <p>The version of the image. If not specified, the latest version is described.</p>
    pub fn version(&self) -> ::std::option::Option<i32> {
        self.version
    }
    /// <p>The alias of the image version.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
}
impl DescribeImageVersionInput {
    /// Creates a new builder-style object to manufacture [`DescribeImageVersionInput`](crate::operation::describe_image_version::DescribeImageVersionInput).
    pub fn builder() -> crate::operation::describe_image_version::builders::DescribeImageVersionInputBuilder {
        crate::operation::describe_image_version::builders::DescribeImageVersionInputBuilder::default()
    }
}

/// A builder for [`DescribeImageVersionInput`](crate::operation::describe_image_version::DescribeImageVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeImageVersionInputBuilder {
    pub(crate) image_name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<i32>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
}
impl DescribeImageVersionInputBuilder {
    /// <p>The name of the image.</p>
    /// This field is required.
    pub fn image_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the image.</p>
    pub fn set_image_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_name = input;
        self
    }
    /// <p>The name of the image.</p>
    pub fn get_image_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_name
    }
    /// <p>The version of the image. If not specified, the latest version is described.</p>
    pub fn version(mut self, input: i32) -> Self {
        self.version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the image. If not specified, the latest version is described.</p>
    pub fn set_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the image. If not specified, the latest version is described.</p>
    pub fn get_version(&self) -> &::std::option::Option<i32> {
        &self.version
    }
    /// <p>The alias of the image version.</p>
    pub fn alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the image version.</p>
    pub fn set_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias = input;
        self
    }
    /// <p>The alias of the image version.</p>
    pub fn get_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias
    }
    /// Consumes the builder and constructs a [`DescribeImageVersionInput`](crate::operation::describe_image_version::DescribeImageVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_image_version::DescribeImageVersionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_image_version::DescribeImageVersionInput {
            image_name: self.image_name,
            version: self.version,
            alias: self.alias,
        })
    }
}
