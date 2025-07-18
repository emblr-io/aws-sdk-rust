// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The value for a given type of <code>UpdateSettings</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateValue {
    /// <p>The OS update related settings.</p>
    pub os_update_settings: ::std::option::Option<crate::types::OsUpdateSettings>,
}
impl UpdateValue {
    /// <p>The OS update related settings.</p>
    pub fn os_update_settings(&self) -> ::std::option::Option<&crate::types::OsUpdateSettings> {
        self.os_update_settings.as_ref()
    }
}
impl UpdateValue {
    /// Creates a new builder-style object to manufacture [`UpdateValue`](crate::types::UpdateValue).
    pub fn builder() -> crate::types::builders::UpdateValueBuilder {
        crate::types::builders::UpdateValueBuilder::default()
    }
}

/// A builder for [`UpdateValue`](crate::types::UpdateValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateValueBuilder {
    pub(crate) os_update_settings: ::std::option::Option<crate::types::OsUpdateSettings>,
}
impl UpdateValueBuilder {
    /// <p>The OS update related settings.</p>
    pub fn os_update_settings(mut self, input: crate::types::OsUpdateSettings) -> Self {
        self.os_update_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The OS update related settings.</p>
    pub fn set_os_update_settings(mut self, input: ::std::option::Option<crate::types::OsUpdateSettings>) -> Self {
        self.os_update_settings = input;
        self
    }
    /// <p>The OS update related settings.</p>
    pub fn get_os_update_settings(&self) -> &::std::option::Option<crate::types::OsUpdateSettings> {
        &self.os_update_settings
    }
    /// Consumes the builder and constructs a [`UpdateValue`](crate::types::UpdateValue).
    pub fn build(self) -> crate::types::UpdateValue {
        crate::types::UpdateValue {
            os_update_settings: self.os_update_settings,
        }
    }
}
