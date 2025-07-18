// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeHyperParameterTuningJobInput {
    /// <p>The name of the tuning job.</p>
    pub hyper_parameter_tuning_job_name: ::std::option::Option<::std::string::String>,
}
impl DescribeHyperParameterTuningJobInput {
    /// <p>The name of the tuning job.</p>
    pub fn hyper_parameter_tuning_job_name(&self) -> ::std::option::Option<&str> {
        self.hyper_parameter_tuning_job_name.as_deref()
    }
}
impl DescribeHyperParameterTuningJobInput {
    /// Creates a new builder-style object to manufacture [`DescribeHyperParameterTuningJobInput`](crate::operation::describe_hyper_parameter_tuning_job::DescribeHyperParameterTuningJobInput).
    pub fn builder() -> crate::operation::describe_hyper_parameter_tuning_job::builders::DescribeHyperParameterTuningJobInputBuilder {
        crate::operation::describe_hyper_parameter_tuning_job::builders::DescribeHyperParameterTuningJobInputBuilder::default()
    }
}

/// A builder for [`DescribeHyperParameterTuningJobInput`](crate::operation::describe_hyper_parameter_tuning_job::DescribeHyperParameterTuningJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeHyperParameterTuningJobInputBuilder {
    pub(crate) hyper_parameter_tuning_job_name: ::std::option::Option<::std::string::String>,
}
impl DescribeHyperParameterTuningJobInputBuilder {
    /// <p>The name of the tuning job.</p>
    /// This field is required.
    pub fn hyper_parameter_tuning_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the tuning job.</p>
    pub fn set_hyper_parameter_tuning_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_name = input;
        self
    }
    /// <p>The name of the tuning job.</p>
    pub fn get_hyper_parameter_tuning_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hyper_parameter_tuning_job_name
    }
    /// Consumes the builder and constructs a [`DescribeHyperParameterTuningJobInput`](crate::operation::describe_hyper_parameter_tuning_job::DescribeHyperParameterTuningJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_hyper_parameter_tuning_job::DescribeHyperParameterTuningJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_hyper_parameter_tuning_job::DescribeHyperParameterTuningJobInput {
                hyper_parameter_tuning_job_name: self.hyper_parameter_tuning_job_name,
            },
        )
    }
}
