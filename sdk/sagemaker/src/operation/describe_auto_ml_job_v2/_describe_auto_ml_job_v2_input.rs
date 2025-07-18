// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAutoMlJobV2Input {
    /// <p>Requests information about an AutoML job V2 using its unique name.</p>
    pub auto_ml_job_name: ::std::option::Option<::std::string::String>,
}
impl DescribeAutoMlJobV2Input {
    /// <p>Requests information about an AutoML job V2 using its unique name.</p>
    pub fn auto_ml_job_name(&self) -> ::std::option::Option<&str> {
        self.auto_ml_job_name.as_deref()
    }
}
impl DescribeAutoMlJobV2Input {
    /// Creates a new builder-style object to manufacture [`DescribeAutoMlJobV2Input`](crate::operation::describe_auto_ml_job_v2::DescribeAutoMlJobV2Input).
    pub fn builder() -> crate::operation::describe_auto_ml_job_v2::builders::DescribeAutoMlJobV2InputBuilder {
        crate::operation::describe_auto_ml_job_v2::builders::DescribeAutoMlJobV2InputBuilder::default()
    }
}

/// A builder for [`DescribeAutoMlJobV2Input`](crate::operation::describe_auto_ml_job_v2::DescribeAutoMlJobV2Input).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAutoMlJobV2InputBuilder {
    pub(crate) auto_ml_job_name: ::std::option::Option<::std::string::String>,
}
impl DescribeAutoMlJobV2InputBuilder {
    /// <p>Requests information about an AutoML job V2 using its unique name.</p>
    /// This field is required.
    pub fn auto_ml_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_ml_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Requests information about an AutoML job V2 using its unique name.</p>
    pub fn set_auto_ml_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_ml_job_name = input;
        self
    }
    /// <p>Requests information about an AutoML job V2 using its unique name.</p>
    pub fn get_auto_ml_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_ml_job_name
    }
    /// Consumes the builder and constructs a [`DescribeAutoMlJobV2Input`](crate::operation::describe_auto_ml_job_v2::DescribeAutoMlJobV2Input).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_auto_ml_job_v2::DescribeAutoMlJobV2Input, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_auto_ml_job_v2::DescribeAutoMlJobV2Input {
            auto_ml_job_name: self.auto_ml_job_name,
        })
    }
}
