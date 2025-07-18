// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportClientBrandingInput {
    /// <p>The directory identifier of the WorkSpace for which you want to import client branding.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The branding information to import for Windows devices.</p>
    pub device_type_windows: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    /// <p>The branding information to import for macOS devices.</p>
    pub device_type_osx: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    /// <p>The branding information to import for Android devices.</p>
    pub device_type_android: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    /// <p>The branding information to import for iOS devices.</p>
    pub device_type_ios: ::std::option::Option<crate::types::IosImportClientBrandingAttributes>,
    /// <p>The branding information to import for Linux devices.</p>
    pub device_type_linux: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    /// <p>The branding information to import for web access.</p>
    pub device_type_web: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
}
impl ImportClientBrandingInput {
    /// <p>The directory identifier of the WorkSpace for which you want to import client branding.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The branding information to import for Windows devices.</p>
    pub fn device_type_windows(&self) -> ::std::option::Option<&crate::types::DefaultImportClientBrandingAttributes> {
        self.device_type_windows.as_ref()
    }
    /// <p>The branding information to import for macOS devices.</p>
    pub fn device_type_osx(&self) -> ::std::option::Option<&crate::types::DefaultImportClientBrandingAttributes> {
        self.device_type_osx.as_ref()
    }
    /// <p>The branding information to import for Android devices.</p>
    pub fn device_type_android(&self) -> ::std::option::Option<&crate::types::DefaultImportClientBrandingAttributes> {
        self.device_type_android.as_ref()
    }
    /// <p>The branding information to import for iOS devices.</p>
    pub fn device_type_ios(&self) -> ::std::option::Option<&crate::types::IosImportClientBrandingAttributes> {
        self.device_type_ios.as_ref()
    }
    /// <p>The branding information to import for Linux devices.</p>
    pub fn device_type_linux(&self) -> ::std::option::Option<&crate::types::DefaultImportClientBrandingAttributes> {
        self.device_type_linux.as_ref()
    }
    /// <p>The branding information to import for web access.</p>
    pub fn device_type_web(&self) -> ::std::option::Option<&crate::types::DefaultImportClientBrandingAttributes> {
        self.device_type_web.as_ref()
    }
}
impl ImportClientBrandingInput {
    /// Creates a new builder-style object to manufacture [`ImportClientBrandingInput`](crate::operation::import_client_branding::ImportClientBrandingInput).
    pub fn builder() -> crate::operation::import_client_branding::builders::ImportClientBrandingInputBuilder {
        crate::operation::import_client_branding::builders::ImportClientBrandingInputBuilder::default()
    }
}

/// A builder for [`ImportClientBrandingInput`](crate::operation::import_client_branding::ImportClientBrandingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportClientBrandingInputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) device_type_windows: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    pub(crate) device_type_osx: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    pub(crate) device_type_android: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    pub(crate) device_type_ios: ::std::option::Option<crate::types::IosImportClientBrandingAttributes>,
    pub(crate) device_type_linux: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
    pub(crate) device_type_web: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>,
}
impl ImportClientBrandingInputBuilder {
    /// <p>The directory identifier of the WorkSpace for which you want to import client branding.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The directory identifier of the WorkSpace for which you want to import client branding.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The directory identifier of the WorkSpace for which you want to import client branding.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The branding information to import for Windows devices.</p>
    pub fn device_type_windows(mut self, input: crate::types::DefaultImportClientBrandingAttributes) -> Self {
        self.device_type_windows = ::std::option::Option::Some(input);
        self
    }
    /// <p>The branding information to import for Windows devices.</p>
    pub fn set_device_type_windows(mut self, input: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>) -> Self {
        self.device_type_windows = input;
        self
    }
    /// <p>The branding information to import for Windows devices.</p>
    pub fn get_device_type_windows(&self) -> &::std::option::Option<crate::types::DefaultImportClientBrandingAttributes> {
        &self.device_type_windows
    }
    /// <p>The branding information to import for macOS devices.</p>
    pub fn device_type_osx(mut self, input: crate::types::DefaultImportClientBrandingAttributes) -> Self {
        self.device_type_osx = ::std::option::Option::Some(input);
        self
    }
    /// <p>The branding information to import for macOS devices.</p>
    pub fn set_device_type_osx(mut self, input: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>) -> Self {
        self.device_type_osx = input;
        self
    }
    /// <p>The branding information to import for macOS devices.</p>
    pub fn get_device_type_osx(&self) -> &::std::option::Option<crate::types::DefaultImportClientBrandingAttributes> {
        &self.device_type_osx
    }
    /// <p>The branding information to import for Android devices.</p>
    pub fn device_type_android(mut self, input: crate::types::DefaultImportClientBrandingAttributes) -> Self {
        self.device_type_android = ::std::option::Option::Some(input);
        self
    }
    /// <p>The branding information to import for Android devices.</p>
    pub fn set_device_type_android(mut self, input: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>) -> Self {
        self.device_type_android = input;
        self
    }
    /// <p>The branding information to import for Android devices.</p>
    pub fn get_device_type_android(&self) -> &::std::option::Option<crate::types::DefaultImportClientBrandingAttributes> {
        &self.device_type_android
    }
    /// <p>The branding information to import for iOS devices.</p>
    pub fn device_type_ios(mut self, input: crate::types::IosImportClientBrandingAttributes) -> Self {
        self.device_type_ios = ::std::option::Option::Some(input);
        self
    }
    /// <p>The branding information to import for iOS devices.</p>
    pub fn set_device_type_ios(mut self, input: ::std::option::Option<crate::types::IosImportClientBrandingAttributes>) -> Self {
        self.device_type_ios = input;
        self
    }
    /// <p>The branding information to import for iOS devices.</p>
    pub fn get_device_type_ios(&self) -> &::std::option::Option<crate::types::IosImportClientBrandingAttributes> {
        &self.device_type_ios
    }
    /// <p>The branding information to import for Linux devices.</p>
    pub fn device_type_linux(mut self, input: crate::types::DefaultImportClientBrandingAttributes) -> Self {
        self.device_type_linux = ::std::option::Option::Some(input);
        self
    }
    /// <p>The branding information to import for Linux devices.</p>
    pub fn set_device_type_linux(mut self, input: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>) -> Self {
        self.device_type_linux = input;
        self
    }
    /// <p>The branding information to import for Linux devices.</p>
    pub fn get_device_type_linux(&self) -> &::std::option::Option<crate::types::DefaultImportClientBrandingAttributes> {
        &self.device_type_linux
    }
    /// <p>The branding information to import for web access.</p>
    pub fn device_type_web(mut self, input: crate::types::DefaultImportClientBrandingAttributes) -> Self {
        self.device_type_web = ::std::option::Option::Some(input);
        self
    }
    /// <p>The branding information to import for web access.</p>
    pub fn set_device_type_web(mut self, input: ::std::option::Option<crate::types::DefaultImportClientBrandingAttributes>) -> Self {
        self.device_type_web = input;
        self
    }
    /// <p>The branding information to import for web access.</p>
    pub fn get_device_type_web(&self) -> &::std::option::Option<crate::types::DefaultImportClientBrandingAttributes> {
        &self.device_type_web
    }
    /// Consumes the builder and constructs a [`ImportClientBrandingInput`](crate::operation::import_client_branding::ImportClientBrandingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::import_client_branding::ImportClientBrandingInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::import_client_branding::ImportClientBrandingInput {
            resource_id: self.resource_id,
            device_type_windows: self.device_type_windows,
            device_type_osx: self.device_type_osx,
            device_type_android: self.device_type_android,
            device_type_ios: self.device_type_ios,
            device_type_linux: self.device_type_linux,
            device_type_web: self.device_type_web,
        })
    }
}
