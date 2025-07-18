// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon QuickSight customizations associated with your Amazon Web Services account or a QuickSight namespace in a specific Amazon Web Services Region.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccountCustomization {
    /// <p>The default theme for this Amazon QuickSight subscription.</p>
    pub default_theme: ::std::option::Option<::std::string::String>,
    /// <p>The default email customization template.</p>
    pub default_email_customization_template: ::std::option::Option<::std::string::String>,
}
impl AccountCustomization {
    /// <p>The default theme for this Amazon QuickSight subscription.</p>
    pub fn default_theme(&self) -> ::std::option::Option<&str> {
        self.default_theme.as_deref()
    }
    /// <p>The default email customization template.</p>
    pub fn default_email_customization_template(&self) -> ::std::option::Option<&str> {
        self.default_email_customization_template.as_deref()
    }
}
impl AccountCustomization {
    /// Creates a new builder-style object to manufacture [`AccountCustomization`](crate::types::AccountCustomization).
    pub fn builder() -> crate::types::builders::AccountCustomizationBuilder {
        crate::types::builders::AccountCustomizationBuilder::default()
    }
}

/// A builder for [`AccountCustomization`](crate::types::AccountCustomization).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountCustomizationBuilder {
    pub(crate) default_theme: ::std::option::Option<::std::string::String>,
    pub(crate) default_email_customization_template: ::std::option::Option<::std::string::String>,
}
impl AccountCustomizationBuilder {
    /// <p>The default theme for this Amazon QuickSight subscription.</p>
    pub fn default_theme(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_theme = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The default theme for this Amazon QuickSight subscription.</p>
    pub fn set_default_theme(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_theme = input;
        self
    }
    /// <p>The default theme for this Amazon QuickSight subscription.</p>
    pub fn get_default_theme(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_theme
    }
    /// <p>The default email customization template.</p>
    pub fn default_email_customization_template(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_email_customization_template = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The default email customization template.</p>
    pub fn set_default_email_customization_template(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_email_customization_template = input;
        self
    }
    /// <p>The default email customization template.</p>
    pub fn get_default_email_customization_template(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_email_customization_template
    }
    /// Consumes the builder and constructs a [`AccountCustomization`](crate::types::AccountCustomization).
    pub fn build(self) -> crate::types::AccountCustomization {
        crate::types::AccountCustomization {
            default_theme: self.default_theme,
            default_email_customization_template: self.default_email_customization_template,
        }
    }
}
