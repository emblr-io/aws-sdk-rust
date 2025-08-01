// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an availability zone.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AvailabilityZone {
    /// <p>The name of the availability zone.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub supported_platforms: ::std::option::Option<::std::vec::Vec<crate::types::SupportedPlatform>>,
}
impl AvailabilityZone {
    /// <p>The name of the availability zone.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_platforms.is_none()`.
    pub fn supported_platforms(&self) -> &[crate::types::SupportedPlatform] {
        self.supported_platforms.as_deref().unwrap_or_default()
    }
}
impl AvailabilityZone {
    /// Creates a new builder-style object to manufacture [`AvailabilityZone`](crate::types::AvailabilityZone).
    pub fn builder() -> crate::types::builders::AvailabilityZoneBuilder {
        crate::types::builders::AvailabilityZoneBuilder::default()
    }
}

/// A builder for [`AvailabilityZone`](crate::types::AvailabilityZone).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AvailabilityZoneBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) supported_platforms: ::std::option::Option<::std::vec::Vec<crate::types::SupportedPlatform>>,
}
impl AvailabilityZoneBuilder {
    /// <p>The name of the availability zone.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the availability zone.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the availability zone.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `supported_platforms`.
    ///
    /// To override the contents of this collection use [`set_supported_platforms`](Self::set_supported_platforms).
    ///
    /// <p></p>
    pub fn supported_platforms(mut self, input: crate::types::SupportedPlatform) -> Self {
        let mut v = self.supported_platforms.unwrap_or_default();
        v.push(input);
        self.supported_platforms = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_supported_platforms(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SupportedPlatform>>) -> Self {
        self.supported_platforms = input;
        self
    }
    /// <p></p>
    pub fn get_supported_platforms(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SupportedPlatform>> {
        &self.supported_platforms
    }
    /// Consumes the builder and constructs a [`AvailabilityZone`](crate::types::AvailabilityZone).
    pub fn build(self) -> crate::types::AvailabilityZone {
        crate::types::AvailabilityZone {
            name: self.name,
            supported_platforms: self.supported_platforms,
        }
    }
}
