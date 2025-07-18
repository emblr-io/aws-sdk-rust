// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Tracks the history of next steps associated with the opportunity. This field captures the actions planned for the future and their timeline.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProfileNextStepsHistory {
    /// <p>Represents the details of the next step recorded, such as follow-up actions or decisions made. This field helps in tracking progress and ensuring alignment with project goals.</p>
    pub value: ::std::string::String,
    /// <p>Indicates the date and time when a particular next step was recorded or planned. This helps in managing the timeline for the opportunity.</p>
    pub time: ::aws_smithy_types::DateTime,
}
impl ProfileNextStepsHistory {
    /// <p>Represents the details of the next step recorded, such as follow-up actions or decisions made. This field helps in tracking progress and ensuring alignment with project goals.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
    /// <p>Indicates the date and time when a particular next step was recorded or planned. This helps in managing the timeline for the opportunity.</p>
    pub fn time(&self) -> &::aws_smithy_types::DateTime {
        &self.time
    }
}
impl ProfileNextStepsHistory {
    /// Creates a new builder-style object to manufacture [`ProfileNextStepsHistory`](crate::types::ProfileNextStepsHistory).
    pub fn builder() -> crate::types::builders::ProfileNextStepsHistoryBuilder {
        crate::types::builders::ProfileNextStepsHistoryBuilder::default()
    }
}

/// A builder for [`ProfileNextStepsHistory`](crate::types::ProfileNextStepsHistory).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProfileNextStepsHistoryBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ProfileNextStepsHistoryBuilder {
    /// <p>Represents the details of the next step recorded, such as follow-up actions or decisions made. This field helps in tracking progress and ensuring alignment with project goals.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Represents the details of the next step recorded, such as follow-up actions or decisions made. This field helps in tracking progress and ensuring alignment with project goals.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>Represents the details of the next step recorded, such as follow-up actions or decisions made. This field helps in tracking progress and ensuring alignment with project goals.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>Indicates the date and time when a particular next step was recorded or planned. This helps in managing the timeline for the opportunity.</p>
    /// This field is required.
    pub fn time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the date and time when a particular next step was recorded or planned. This helps in managing the timeline for the opportunity.</p>
    pub fn set_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.time = input;
        self
    }
    /// <p>Indicates the date and time when a particular next step was recorded or planned. This helps in managing the timeline for the opportunity.</p>
    pub fn get_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.time
    }
    /// Consumes the builder and constructs a [`ProfileNextStepsHistory`](crate::types::ProfileNextStepsHistory).
    /// This method will fail if any of the following fields are not set:
    /// - [`value`](crate::types::builders::ProfileNextStepsHistoryBuilder::value)
    /// - [`time`](crate::types::builders::ProfileNextStepsHistoryBuilder::time)
    pub fn build(self) -> ::std::result::Result<crate::types::ProfileNextStepsHistory, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProfileNextStepsHistory {
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building ProfileNextStepsHistory",
                )
            })?,
            time: self.time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "time",
                    "time was not specified but it is required when building ProfileNextStepsHistory",
                )
            })?,
        })
    }
}
