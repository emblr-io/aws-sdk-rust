// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateWebAppCustomizationInput {
    /// <p>Provide the identifier of the web app that you are updating.</p>
    pub web_app_id: ::std::option::Option<::std::string::String>,
    /// <p>Provide an updated title.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>Specify logo file data string (in base64 encoding).</p>
    pub logo_file: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Specify an icon file data string (in base64 encoding).</p>
    pub favicon_file: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl UpdateWebAppCustomizationInput {
    /// <p>Provide the identifier of the web app that you are updating.</p>
    pub fn web_app_id(&self) -> ::std::option::Option<&str> {
        self.web_app_id.as_deref()
    }
    /// <p>Provide an updated title.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>Specify logo file data string (in base64 encoding).</p>
    pub fn logo_file(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.logo_file.as_ref()
    }
    /// <p>Specify an icon file data string (in base64 encoding).</p>
    pub fn favicon_file(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.favicon_file.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateWebAppCustomizationInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateWebAppCustomizationInput");
        formatter.field("web_app_id", &self.web_app_id);
        formatter.field("title", &self.title);
        formatter.field("logo_file", &"*** Sensitive Data Redacted ***");
        formatter.field("favicon_file", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl UpdateWebAppCustomizationInput {
    /// Creates a new builder-style object to manufacture [`UpdateWebAppCustomizationInput`](crate::operation::update_web_app_customization::UpdateWebAppCustomizationInput).
    pub fn builder() -> crate::operation::update_web_app_customization::builders::UpdateWebAppCustomizationInputBuilder {
        crate::operation::update_web_app_customization::builders::UpdateWebAppCustomizationInputBuilder::default()
    }
}

/// A builder for [`UpdateWebAppCustomizationInput`](crate::operation::update_web_app_customization::UpdateWebAppCustomizationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateWebAppCustomizationInputBuilder {
    pub(crate) web_app_id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) logo_file: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) favicon_file: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl UpdateWebAppCustomizationInputBuilder {
    /// <p>Provide the identifier of the web app that you are updating.</p>
    /// This field is required.
    pub fn web_app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.web_app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provide the identifier of the web app that you are updating.</p>
    pub fn set_web_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.web_app_id = input;
        self
    }
    /// <p>Provide the identifier of the web app that you are updating.</p>
    pub fn get_web_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.web_app_id
    }
    /// <p>Provide an updated title.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provide an updated title.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>Provide an updated title.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>Specify logo file data string (in base64 encoding).</p>
    pub fn logo_file(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.logo_file = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify logo file data string (in base64 encoding).</p>
    pub fn set_logo_file(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.logo_file = input;
        self
    }
    /// <p>Specify logo file data string (in base64 encoding).</p>
    pub fn get_logo_file(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.logo_file
    }
    /// <p>Specify an icon file data string (in base64 encoding).</p>
    pub fn favicon_file(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.favicon_file = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify an icon file data string (in base64 encoding).</p>
    pub fn set_favicon_file(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.favicon_file = input;
        self
    }
    /// <p>Specify an icon file data string (in base64 encoding).</p>
    pub fn get_favicon_file(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.favicon_file
    }
    /// Consumes the builder and constructs a [`UpdateWebAppCustomizationInput`](crate::operation::update_web_app_customization::UpdateWebAppCustomizationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_web_app_customization::UpdateWebAppCustomizationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_web_app_customization::UpdateWebAppCustomizationInput {
            web_app_id: self.web_app_id,
            title: self.title,
            logo_file: self.logo_file,
            favicon_file: self.favicon_file,
        })
    }
}
impl ::std::fmt::Debug for UpdateWebAppCustomizationInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateWebAppCustomizationInputBuilder");
        formatter.field("web_app_id", &self.web_app_id);
        formatter.field("title", &self.title);
        formatter.field("logo_file", &"*** Sensitive Data Redacted ***");
        formatter.field("favicon_file", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
