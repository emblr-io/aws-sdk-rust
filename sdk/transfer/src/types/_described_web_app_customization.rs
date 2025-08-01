// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains the customization fields for the web app. You can provide a title, logo, and icon to customize the appearance of your web app.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DescribedWebAppCustomization {
    /// <p>Returns the Amazon Resource Name (ARN) for the web app.</p>
    pub arn: ::std::string::String,
    /// <p>Returns the unique identifier for your web app.</p>
    pub web_app_id: ::std::string::String,
    /// <p>Returns the page title that you defined for your web app.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>Returns a logo file data string (in base64 encoding).</p>
    pub logo_file: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Returns an icon file data string (in base64 encoding).</p>
    pub favicon_file: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl DescribedWebAppCustomization {
    /// <p>Returns the Amazon Resource Name (ARN) for the web app.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>Returns the unique identifier for your web app.</p>
    pub fn web_app_id(&self) -> &str {
        use std::ops::Deref;
        self.web_app_id.deref()
    }
    /// <p>Returns the page title that you defined for your web app.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>Returns a logo file data string (in base64 encoding).</p>
    pub fn logo_file(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.logo_file.as_ref()
    }
    /// <p>Returns an icon file data string (in base64 encoding).</p>
    pub fn favicon_file(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.favicon_file.as_ref()
    }
}
impl ::std::fmt::Debug for DescribedWebAppCustomization {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DescribedWebAppCustomization");
        formatter.field("arn", &self.arn);
        formatter.field("web_app_id", &self.web_app_id);
        formatter.field("title", &self.title);
        formatter.field("logo_file", &"*** Sensitive Data Redacted ***");
        formatter.field("favicon_file", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl DescribedWebAppCustomization {
    /// Creates a new builder-style object to manufacture [`DescribedWebAppCustomization`](crate::types::DescribedWebAppCustomization).
    pub fn builder() -> crate::types::builders::DescribedWebAppCustomizationBuilder {
        crate::types::builders::DescribedWebAppCustomizationBuilder::default()
    }
}

/// A builder for [`DescribedWebAppCustomization`](crate::types::DescribedWebAppCustomization).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DescribedWebAppCustomizationBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) web_app_id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) logo_file: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) favicon_file: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl DescribedWebAppCustomizationBuilder {
    /// <p>Returns the Amazon Resource Name (ARN) for the web app.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the Amazon Resource Name (ARN) for the web app.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>Returns the Amazon Resource Name (ARN) for the web app.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Returns the unique identifier for your web app.</p>
    /// This field is required.
    pub fn web_app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.web_app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the unique identifier for your web app.</p>
    pub fn set_web_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.web_app_id = input;
        self
    }
    /// <p>Returns the unique identifier for your web app.</p>
    pub fn get_web_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.web_app_id
    }
    /// <p>Returns the page title that you defined for your web app.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the page title that you defined for your web app.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>Returns the page title that you defined for your web app.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>Returns a logo file data string (in base64 encoding).</p>
    pub fn logo_file(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.logo_file = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns a logo file data string (in base64 encoding).</p>
    pub fn set_logo_file(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.logo_file = input;
        self
    }
    /// <p>Returns a logo file data string (in base64 encoding).</p>
    pub fn get_logo_file(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.logo_file
    }
    /// <p>Returns an icon file data string (in base64 encoding).</p>
    pub fn favicon_file(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.favicon_file = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns an icon file data string (in base64 encoding).</p>
    pub fn set_favicon_file(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.favicon_file = input;
        self
    }
    /// <p>Returns an icon file data string (in base64 encoding).</p>
    pub fn get_favicon_file(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.favicon_file
    }
    /// Consumes the builder and constructs a [`DescribedWebAppCustomization`](crate::types::DescribedWebAppCustomization).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::DescribedWebAppCustomizationBuilder::arn)
    /// - [`web_app_id`](crate::types::builders::DescribedWebAppCustomizationBuilder::web_app_id)
    pub fn build(self) -> ::std::result::Result<crate::types::DescribedWebAppCustomization, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DescribedWebAppCustomization {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building DescribedWebAppCustomization",
                )
            })?,
            web_app_id: self.web_app_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "web_app_id",
                    "web_app_id was not specified but it is required when building DescribedWebAppCustomization",
                )
            })?,
            title: self.title,
            logo_file: self.logo_file,
            favicon_file: self.favicon_file,
        })
    }
}
impl ::std::fmt::Debug for DescribedWebAppCustomizationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DescribedWebAppCustomizationBuilder");
        formatter.field("arn", &self.arn);
        formatter.field("web_app_id", &self.web_app_id);
        formatter.field("title", &self.title);
        formatter.field("logo_file", &"*** Sensitive Data Redacted ***");
        formatter.field("favicon_file", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
