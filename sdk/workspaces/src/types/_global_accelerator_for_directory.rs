// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the Global Accelerator for directory</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GlobalAcceleratorForDirectory {
    /// <p>Indicates if Global Accelerator for directory is enabled or disabled.</p>
    pub mode: crate::types::AgaModeForDirectoryEnum,
    /// <p>Indicates the preferred protocol for Global Accelerator.</p>
    pub preferred_protocol: ::std::option::Option<crate::types::AgaPreferredProtocolForDirectory>,
}
impl GlobalAcceleratorForDirectory {
    /// <p>Indicates if Global Accelerator for directory is enabled or disabled.</p>
    pub fn mode(&self) -> &crate::types::AgaModeForDirectoryEnum {
        &self.mode
    }
    /// <p>Indicates the preferred protocol for Global Accelerator.</p>
    pub fn preferred_protocol(&self) -> ::std::option::Option<&crate::types::AgaPreferredProtocolForDirectory> {
        self.preferred_protocol.as_ref()
    }
}
impl GlobalAcceleratorForDirectory {
    /// Creates a new builder-style object to manufacture [`GlobalAcceleratorForDirectory`](crate::types::GlobalAcceleratorForDirectory).
    pub fn builder() -> crate::types::builders::GlobalAcceleratorForDirectoryBuilder {
        crate::types::builders::GlobalAcceleratorForDirectoryBuilder::default()
    }
}

/// A builder for [`GlobalAcceleratorForDirectory`](crate::types::GlobalAcceleratorForDirectory).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GlobalAcceleratorForDirectoryBuilder {
    pub(crate) mode: ::std::option::Option<crate::types::AgaModeForDirectoryEnum>,
    pub(crate) preferred_protocol: ::std::option::Option<crate::types::AgaPreferredProtocolForDirectory>,
}
impl GlobalAcceleratorForDirectoryBuilder {
    /// <p>Indicates if Global Accelerator for directory is enabled or disabled.</p>
    /// This field is required.
    pub fn mode(mut self, input: crate::types::AgaModeForDirectoryEnum) -> Self {
        self.mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if Global Accelerator for directory is enabled or disabled.</p>
    pub fn set_mode(mut self, input: ::std::option::Option<crate::types::AgaModeForDirectoryEnum>) -> Self {
        self.mode = input;
        self
    }
    /// <p>Indicates if Global Accelerator for directory is enabled or disabled.</p>
    pub fn get_mode(&self) -> &::std::option::Option<crate::types::AgaModeForDirectoryEnum> {
        &self.mode
    }
    /// <p>Indicates the preferred protocol for Global Accelerator.</p>
    pub fn preferred_protocol(mut self, input: crate::types::AgaPreferredProtocolForDirectory) -> Self {
        self.preferred_protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the preferred protocol for Global Accelerator.</p>
    pub fn set_preferred_protocol(mut self, input: ::std::option::Option<crate::types::AgaPreferredProtocolForDirectory>) -> Self {
        self.preferred_protocol = input;
        self
    }
    /// <p>Indicates the preferred protocol for Global Accelerator.</p>
    pub fn get_preferred_protocol(&self) -> &::std::option::Option<crate::types::AgaPreferredProtocolForDirectory> {
        &self.preferred_protocol
    }
    /// Consumes the builder and constructs a [`GlobalAcceleratorForDirectory`](crate::types::GlobalAcceleratorForDirectory).
    /// This method will fail if any of the following fields are not set:
    /// - [`mode`](crate::types::builders::GlobalAcceleratorForDirectoryBuilder::mode)
    pub fn build(self) -> ::std::result::Result<crate::types::GlobalAcceleratorForDirectory, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GlobalAcceleratorForDirectory {
            mode: self.mode.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "mode",
                    "mode was not specified but it is required when building GlobalAcceleratorForDirectory",
                )
            })?,
            preferred_protocol: self.preferred_protocol,
        })
    }
}
