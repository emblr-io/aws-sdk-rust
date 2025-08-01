// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLocationFsxLustreInput {
    /// <p>The Amazon Resource Name (ARN) of the FSx for Lustre location to describe.</p>
    pub location_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeLocationFsxLustreInput {
    /// <p>The Amazon Resource Name (ARN) of the FSx for Lustre location to describe.</p>
    pub fn location_arn(&self) -> ::std::option::Option<&str> {
        self.location_arn.as_deref()
    }
}
impl DescribeLocationFsxLustreInput {
    /// Creates a new builder-style object to manufacture [`DescribeLocationFsxLustreInput`](crate::operation::describe_location_fsx_lustre::DescribeLocationFsxLustreInput).
    pub fn builder() -> crate::operation::describe_location_fsx_lustre::builders::DescribeLocationFsxLustreInputBuilder {
        crate::operation::describe_location_fsx_lustre::builders::DescribeLocationFsxLustreInputBuilder::default()
    }
}

/// A builder for [`DescribeLocationFsxLustreInput`](crate::operation::describe_location_fsx_lustre::DescribeLocationFsxLustreInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLocationFsxLustreInputBuilder {
    pub(crate) location_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeLocationFsxLustreInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the FSx for Lustre location to describe.</p>
    /// This field is required.
    pub fn location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the FSx for Lustre location to describe.</p>
    pub fn set_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the FSx for Lustre location to describe.</p>
    pub fn get_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_arn
    }
    /// Consumes the builder and constructs a [`DescribeLocationFsxLustreInput`](crate::operation::describe_location_fsx_lustre::DescribeLocationFsxLustreInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_location_fsx_lustre::DescribeLocationFsxLustreInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_location_fsx_lustre::DescribeLocationFsxLustreInput {
            location_arn: self.location_arn,
        })
    }
}
