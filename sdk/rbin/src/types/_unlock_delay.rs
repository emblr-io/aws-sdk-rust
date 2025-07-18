// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the retention rule unlock delay. The unlock delay is the period after which a retention rule can be modified or edited after it has been unlocked by a user with the required permissions. The retention rule can't be modified or deleted during the unlock delay.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnlockDelay {
    /// <p>The unlock delay period, measured in the unit specified for <b> UnlockDelayUnit</b>.</p>
    pub unlock_delay_value: i32,
    /// <p>The unit of time in which to measure the unlock delay. Currently, the unlock delay can be measure only in days.</p>
    pub unlock_delay_unit: crate::types::UnlockDelayUnit,
}
impl UnlockDelay {
    /// <p>The unlock delay period, measured in the unit specified for <b> UnlockDelayUnit</b>.</p>
    pub fn unlock_delay_value(&self) -> i32 {
        self.unlock_delay_value
    }
    /// <p>The unit of time in which to measure the unlock delay. Currently, the unlock delay can be measure only in days.</p>
    pub fn unlock_delay_unit(&self) -> &crate::types::UnlockDelayUnit {
        &self.unlock_delay_unit
    }
}
impl UnlockDelay {
    /// Creates a new builder-style object to manufacture [`UnlockDelay`](crate::types::UnlockDelay).
    pub fn builder() -> crate::types::builders::UnlockDelayBuilder {
        crate::types::builders::UnlockDelayBuilder::default()
    }
}

/// A builder for [`UnlockDelay`](crate::types::UnlockDelay).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnlockDelayBuilder {
    pub(crate) unlock_delay_value: ::std::option::Option<i32>,
    pub(crate) unlock_delay_unit: ::std::option::Option<crate::types::UnlockDelayUnit>,
}
impl UnlockDelayBuilder {
    /// <p>The unlock delay period, measured in the unit specified for <b> UnlockDelayUnit</b>.</p>
    /// This field is required.
    pub fn unlock_delay_value(mut self, input: i32) -> Self {
        self.unlock_delay_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unlock delay period, measured in the unit specified for <b> UnlockDelayUnit</b>.</p>
    pub fn set_unlock_delay_value(mut self, input: ::std::option::Option<i32>) -> Self {
        self.unlock_delay_value = input;
        self
    }
    /// <p>The unlock delay period, measured in the unit specified for <b> UnlockDelayUnit</b>.</p>
    pub fn get_unlock_delay_value(&self) -> &::std::option::Option<i32> {
        &self.unlock_delay_value
    }
    /// <p>The unit of time in which to measure the unlock delay. Currently, the unlock delay can be measure only in days.</p>
    /// This field is required.
    pub fn unlock_delay_unit(mut self, input: crate::types::UnlockDelayUnit) -> Self {
        self.unlock_delay_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unit of time in which to measure the unlock delay. Currently, the unlock delay can be measure only in days.</p>
    pub fn set_unlock_delay_unit(mut self, input: ::std::option::Option<crate::types::UnlockDelayUnit>) -> Self {
        self.unlock_delay_unit = input;
        self
    }
    /// <p>The unit of time in which to measure the unlock delay. Currently, the unlock delay can be measure only in days.</p>
    pub fn get_unlock_delay_unit(&self) -> &::std::option::Option<crate::types::UnlockDelayUnit> {
        &self.unlock_delay_unit
    }
    /// Consumes the builder and constructs a [`UnlockDelay`](crate::types::UnlockDelay).
    /// This method will fail if any of the following fields are not set:
    /// - [`unlock_delay_value`](crate::types::builders::UnlockDelayBuilder::unlock_delay_value)
    /// - [`unlock_delay_unit`](crate::types::builders::UnlockDelayBuilder::unlock_delay_unit)
    pub fn build(self) -> ::std::result::Result<crate::types::UnlockDelay, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::UnlockDelay {
            unlock_delay_value: self.unlock_delay_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unlock_delay_value",
                    "unlock_delay_value was not specified but it is required when building UnlockDelay",
                )
            })?,
            unlock_delay_unit: self.unlock_delay_unit.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unlock_delay_unit",
                    "unlock_delay_unit was not specified but it is required when building UnlockDelay",
                )
            })?,
        })
    }
}
