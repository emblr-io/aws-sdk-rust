// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A collection of space sharing settings.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SpaceSharingSettings {
    /// <p>Specifies the sharing type of the space.</p>
    pub sharing_type: ::std::option::Option<crate::types::SharingType>,
}
impl SpaceSharingSettings {
    /// <p>Specifies the sharing type of the space.</p>
    pub fn sharing_type(&self) -> ::std::option::Option<&crate::types::SharingType> {
        self.sharing_type.as_ref()
    }
}
impl SpaceSharingSettings {
    /// Creates a new builder-style object to manufacture [`SpaceSharingSettings`](crate::types::SpaceSharingSettings).
    pub fn builder() -> crate::types::builders::SpaceSharingSettingsBuilder {
        crate::types::builders::SpaceSharingSettingsBuilder::default()
    }
}

/// A builder for [`SpaceSharingSettings`](crate::types::SpaceSharingSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SpaceSharingSettingsBuilder {
    pub(crate) sharing_type: ::std::option::Option<crate::types::SharingType>,
}
impl SpaceSharingSettingsBuilder {
    /// <p>Specifies the sharing type of the space.</p>
    /// This field is required.
    pub fn sharing_type(mut self, input: crate::types::SharingType) -> Self {
        self.sharing_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the sharing type of the space.</p>
    pub fn set_sharing_type(mut self, input: ::std::option::Option<crate::types::SharingType>) -> Self {
        self.sharing_type = input;
        self
    }
    /// <p>Specifies the sharing type of the space.</p>
    pub fn get_sharing_type(&self) -> &::std::option::Option<crate::types::SharingType> {
        &self.sharing_type
    }
    /// Consumes the builder and constructs a [`SpaceSharingSettings`](crate::types::SpaceSharingSettings).
    pub fn build(self) -> crate::types::SpaceSharingSettings {
        crate::types::SpaceSharingSettings {
            sharing_type: self.sharing_type,
        }
    }
}
