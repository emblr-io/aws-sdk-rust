// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The cluster management and job scheduling software associated with the cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Scheduler {
    /// <p>The software Amazon Web Services PCS uses to manage cluster scaling and job scheduling.</p>
    pub r#type: crate::types::SchedulerType,
    /// <p>The version of the specified scheduling software that Amazon Web Services PCS uses to manage cluster scaling and job scheduling. For more information, see <a href="https://docs.aws.amazon.com/pcs/latest/userguide/slurm-versions.html">Slurm versions in Amazon Web Services PCS</a> in the <i>Amazon Web Services PCS User Guide</i>.</p>
    /// <p>Valid Values: <code>23.11 | 24.05 | 24.11</code></p>
    pub version: ::std::string::String,
}
impl Scheduler {
    /// <p>The software Amazon Web Services PCS uses to manage cluster scaling and job scheduling.</p>
    pub fn r#type(&self) -> &crate::types::SchedulerType {
        &self.r#type
    }
    /// <p>The version of the specified scheduling software that Amazon Web Services PCS uses to manage cluster scaling and job scheduling. For more information, see <a href="https://docs.aws.amazon.com/pcs/latest/userguide/slurm-versions.html">Slurm versions in Amazon Web Services PCS</a> in the <i>Amazon Web Services PCS User Guide</i>.</p>
    /// <p>Valid Values: <code>23.11 | 24.05 | 24.11</code></p>
    pub fn version(&self) -> &str {
        use std::ops::Deref;
        self.version.deref()
    }
}
impl Scheduler {
    /// Creates a new builder-style object to manufacture [`Scheduler`](crate::types::Scheduler).
    pub fn builder() -> crate::types::builders::SchedulerBuilder {
        crate::types::builders::SchedulerBuilder::default()
    }
}

/// A builder for [`Scheduler`](crate::types::Scheduler).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SchedulerBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::SchedulerType>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl SchedulerBuilder {
    /// <p>The software Amazon Web Services PCS uses to manage cluster scaling and job scheduling.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::SchedulerType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The software Amazon Web Services PCS uses to manage cluster scaling and job scheduling.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::SchedulerType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The software Amazon Web Services PCS uses to manage cluster scaling and job scheduling.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::SchedulerType> {
        &self.r#type
    }
    /// <p>The version of the specified scheduling software that Amazon Web Services PCS uses to manage cluster scaling and job scheduling. For more information, see <a href="https://docs.aws.amazon.com/pcs/latest/userguide/slurm-versions.html">Slurm versions in Amazon Web Services PCS</a> in the <i>Amazon Web Services PCS User Guide</i>.</p>
    /// <p>Valid Values: <code>23.11 | 24.05 | 24.11</code></p>
    /// This field is required.
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the specified scheduling software that Amazon Web Services PCS uses to manage cluster scaling and job scheduling. For more information, see <a href="https://docs.aws.amazon.com/pcs/latest/userguide/slurm-versions.html">Slurm versions in Amazon Web Services PCS</a> in the <i>Amazon Web Services PCS User Guide</i>.</p>
    /// <p>Valid Values: <code>23.11 | 24.05 | 24.11</code></p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the specified scheduling software that Amazon Web Services PCS uses to manage cluster scaling and job scheduling. For more information, see <a href="https://docs.aws.amazon.com/pcs/latest/userguide/slurm-versions.html">Slurm versions in Amazon Web Services PCS</a> in the <i>Amazon Web Services PCS User Guide</i>.</p>
    /// <p>Valid Values: <code>23.11 | 24.05 | 24.11</code></p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`Scheduler`](crate::types::Scheduler).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::SchedulerBuilder::type)
    /// - [`version`](crate::types::builders::SchedulerBuilder::version)
    pub fn build(self) -> ::std::result::Result<crate::types::Scheduler, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Scheduler {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building Scheduler",
                )
            })?,
            version: self.version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "version",
                    "version was not specified but it is required when building Scheduler",
                )
            })?,
        })
    }
}
