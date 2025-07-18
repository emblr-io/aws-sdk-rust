// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information needed to set the timer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SetTimerAction {
    /// <p>The name of the timer.</p>
    pub timer_name: ::std::string::String,
    /// <p>The number of seconds until the timer expires. The minimum value is 60 seconds to ensure accuracy. The maximum value is 31622400 seconds.</p>
    #[deprecated(
        note = "seconds is deprecated. You can use durationExpression for SetTimerAction. The value of seconds can be used as a string expression for durationExpression."
    )]
    pub seconds: ::std::option::Option<i32>,
    /// <p>The duration of the timer, in seconds. You can use a string expression that includes numbers, variables (<code>$variable.<variable-name></variable-name></code>), and input values (<code>$input.<input-name>
    /// .
    /// <path-to-datum></path-to-datum>
    /// </input-name></code>) as the duration. The range of the duration is 1-31622400 seconds. To ensure accuracy, the minimum duration is 60 seconds. The evaluated result of the duration is rounded down to the nearest whole number.</p>
    pub duration_expression: ::std::option::Option<::std::string::String>,
}
impl SetTimerAction {
    /// <p>The name of the timer.</p>
    pub fn timer_name(&self) -> &str {
        use std::ops::Deref;
        self.timer_name.deref()
    }
    /// <p>The number of seconds until the timer expires. The minimum value is 60 seconds to ensure accuracy. The maximum value is 31622400 seconds.</p>
    #[deprecated(
        note = "seconds is deprecated. You can use durationExpression for SetTimerAction. The value of seconds can be used as a string expression for durationExpression."
    )]
    pub fn seconds(&self) -> ::std::option::Option<i32> {
        self.seconds
    }
    /// <p>The duration of the timer, in seconds. You can use a string expression that includes numbers, variables (<code>$variable.<variable-name></variable-name></code>), and input values (<code>$input.<input-name>
    /// .
    /// <path-to-datum></path-to-datum>
    /// </input-name></code>) as the duration. The range of the duration is 1-31622400 seconds. To ensure accuracy, the minimum duration is 60 seconds. The evaluated result of the duration is rounded down to the nearest whole number.</p>
    pub fn duration_expression(&self) -> ::std::option::Option<&str> {
        self.duration_expression.as_deref()
    }
}
impl SetTimerAction {
    /// Creates a new builder-style object to manufacture [`SetTimerAction`](crate::types::SetTimerAction).
    pub fn builder() -> crate::types::builders::SetTimerActionBuilder {
        crate::types::builders::SetTimerActionBuilder::default()
    }
}

/// A builder for [`SetTimerAction`](crate::types::SetTimerAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SetTimerActionBuilder {
    pub(crate) timer_name: ::std::option::Option<::std::string::String>,
    pub(crate) seconds: ::std::option::Option<i32>,
    pub(crate) duration_expression: ::std::option::Option<::std::string::String>,
}
impl SetTimerActionBuilder {
    /// <p>The name of the timer.</p>
    /// This field is required.
    pub fn timer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the timer.</p>
    pub fn set_timer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timer_name = input;
        self
    }
    /// <p>The name of the timer.</p>
    pub fn get_timer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.timer_name
    }
    /// <p>The number of seconds until the timer expires. The minimum value is 60 seconds to ensure accuracy. The maximum value is 31622400 seconds.</p>
    #[deprecated(
        note = "seconds is deprecated. You can use durationExpression for SetTimerAction. The value of seconds can be used as a string expression for durationExpression."
    )]
    pub fn seconds(mut self, input: i32) -> Self {
        self.seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of seconds until the timer expires. The minimum value is 60 seconds to ensure accuracy. The maximum value is 31622400 seconds.</p>
    #[deprecated(
        note = "seconds is deprecated. You can use durationExpression for SetTimerAction. The value of seconds can be used as a string expression for durationExpression."
    )]
    pub fn set_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.seconds = input;
        self
    }
    /// <p>The number of seconds until the timer expires. The minimum value is 60 seconds to ensure accuracy. The maximum value is 31622400 seconds.</p>
    #[deprecated(
        note = "seconds is deprecated. You can use durationExpression for SetTimerAction. The value of seconds can be used as a string expression for durationExpression."
    )]
    pub fn get_seconds(&self) -> &::std::option::Option<i32> {
        &self.seconds
    }
    /// <p>The duration of the timer, in seconds. You can use a string expression that includes numbers, variables (<code>$variable.<variable-name></variable-name></code>), and input values (<code>$input.<input-name>
    /// .
    /// <path-to-datum></path-to-datum>
    /// </input-name></code>) as the duration. The range of the duration is 1-31622400 seconds. To ensure accuracy, the minimum duration is 60 seconds. The evaluated result of the duration is rounded down to the nearest whole number.</p>
    pub fn duration_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.duration_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The duration of the timer, in seconds. You can use a string expression that includes numbers, variables (<code>$variable.<variable-name></variable-name></code>), and input values (<code>$input.<input-name>
    /// .
    /// <path-to-datum></path-to-datum>
    /// </input-name></code>) as the duration. The range of the duration is 1-31622400 seconds. To ensure accuracy, the minimum duration is 60 seconds. The evaluated result of the duration is rounded down to the nearest whole number.</p>
    pub fn set_duration_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.duration_expression = input;
        self
    }
    /// <p>The duration of the timer, in seconds. You can use a string expression that includes numbers, variables (<code>$variable.<variable-name></variable-name></code>), and input values (<code>$input.<input-name>
    /// .
    /// <path-to-datum></path-to-datum>
    /// </input-name></code>) as the duration. The range of the duration is 1-31622400 seconds. To ensure accuracy, the minimum duration is 60 seconds. The evaluated result of the duration is rounded down to the nearest whole number.</p>
    pub fn get_duration_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.duration_expression
    }
    /// Consumes the builder and constructs a [`SetTimerAction`](crate::types::SetTimerAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`timer_name`](crate::types::builders::SetTimerActionBuilder::timer_name)
    pub fn build(self) -> ::std::result::Result<crate::types::SetTimerAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SetTimerAction {
            timer_name: self.timer_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "timer_name",
                    "timer_name was not specified but it is required when building SetTimerAction",
                )
            })?,
            seconds: self.seconds,
            duration_expression: self.duration_expression,
        })
    }
}
