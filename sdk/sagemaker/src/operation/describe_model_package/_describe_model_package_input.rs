// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeModelPackageInput {
    /// <p>The name or Amazon Resource Name (ARN) of the model package to describe.</p>
    /// <p>When you specify a name, the name must have 1 to 63 characters. Valid characters are a-z, A-Z, 0-9, and - (hyphen).</p>
    pub model_package_name: ::std::option::Option<::std::string::String>,
}
impl DescribeModelPackageInput {
    /// <p>The name or Amazon Resource Name (ARN) of the model package to describe.</p>
    /// <p>When you specify a name, the name must have 1 to 63 characters. Valid characters are a-z, A-Z, 0-9, and - (hyphen).</p>
    pub fn model_package_name(&self) -> ::std::option::Option<&str> {
        self.model_package_name.as_deref()
    }
}
impl DescribeModelPackageInput {
    /// Creates a new builder-style object to manufacture [`DescribeModelPackageInput`](crate::operation::describe_model_package::DescribeModelPackageInput).
    pub fn builder() -> crate::operation::describe_model_package::builders::DescribeModelPackageInputBuilder {
        crate::operation::describe_model_package::builders::DescribeModelPackageInputBuilder::default()
    }
}

/// A builder for [`DescribeModelPackageInput`](crate::operation::describe_model_package::DescribeModelPackageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeModelPackageInputBuilder {
    pub(crate) model_package_name: ::std::option::Option<::std::string::String>,
}
impl DescribeModelPackageInputBuilder {
    /// <p>The name or Amazon Resource Name (ARN) of the model package to describe.</p>
    /// <p>When you specify a name, the name must have 1 to 63 characters. Valid characters are a-z, A-Z, 0-9, and - (hyphen).</p>
    /// This field is required.
    pub fn model_package_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_package_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the model package to describe.</p>
    /// <p>When you specify a name, the name must have 1 to 63 characters. Valid characters are a-z, A-Z, 0-9, and - (hyphen).</p>
    pub fn set_model_package_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_package_name = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the model package to describe.</p>
    /// <p>When you specify a name, the name must have 1 to 63 characters. Valid characters are a-z, A-Z, 0-9, and - (hyphen).</p>
    pub fn get_model_package_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_package_name
    }
    /// Consumes the builder and constructs a [`DescribeModelPackageInput`](crate::operation::describe_model_package::DescribeModelPackageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_model_package::DescribeModelPackageInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_model_package::DescribeModelPackageInput {
            model_package_name: self.model_package_name,
        })
    }
}
