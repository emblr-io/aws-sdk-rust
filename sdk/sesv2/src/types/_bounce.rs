// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a <code>Bounce</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Bounce {
    /// <p>The type of the bounce, as determined by SES. Can be one of <code>UNDETERMINED</code>, <code>TRANSIENT</code>, or <code>PERMANENT</code></p>
    pub bounce_type: ::std::option::Option<crate::types::BounceType>,
    /// <p>The subtype of the bounce, as determined by SES.</p>
    pub bounce_sub_type: ::std::option::Option<::std::string::String>,
    /// <p>The status code issued by the reporting Message Transfer Authority (MTA). This field only appears if a delivery status notification (DSN) was attached to the bounce and the <code>Diagnostic-Code</code> was provided in the DSN.</p>
    pub diagnostic_code: ::std::option::Option<::std::string::String>,
}
impl Bounce {
    /// <p>The type of the bounce, as determined by SES. Can be one of <code>UNDETERMINED</code>, <code>TRANSIENT</code>, or <code>PERMANENT</code></p>
    pub fn bounce_type(&self) -> ::std::option::Option<&crate::types::BounceType> {
        self.bounce_type.as_ref()
    }
    /// <p>The subtype of the bounce, as determined by SES.</p>
    pub fn bounce_sub_type(&self) -> ::std::option::Option<&str> {
        self.bounce_sub_type.as_deref()
    }
    /// <p>The status code issued by the reporting Message Transfer Authority (MTA). This field only appears if a delivery status notification (DSN) was attached to the bounce and the <code>Diagnostic-Code</code> was provided in the DSN.</p>
    pub fn diagnostic_code(&self) -> ::std::option::Option<&str> {
        self.diagnostic_code.as_deref()
    }
}
impl Bounce {
    /// Creates a new builder-style object to manufacture [`Bounce`](crate::types::Bounce).
    pub fn builder() -> crate::types::builders::BounceBuilder {
        crate::types::builders::BounceBuilder::default()
    }
}

/// A builder for [`Bounce`](crate::types::Bounce).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BounceBuilder {
    pub(crate) bounce_type: ::std::option::Option<crate::types::BounceType>,
    pub(crate) bounce_sub_type: ::std::option::Option<::std::string::String>,
    pub(crate) diagnostic_code: ::std::option::Option<::std::string::String>,
}
impl BounceBuilder {
    /// <p>The type of the bounce, as determined by SES. Can be one of <code>UNDETERMINED</code>, <code>TRANSIENT</code>, or <code>PERMANENT</code></p>
    pub fn bounce_type(mut self, input: crate::types::BounceType) -> Self {
        self.bounce_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the bounce, as determined by SES. Can be one of <code>UNDETERMINED</code>, <code>TRANSIENT</code>, or <code>PERMANENT</code></p>
    pub fn set_bounce_type(mut self, input: ::std::option::Option<crate::types::BounceType>) -> Self {
        self.bounce_type = input;
        self
    }
    /// <p>The type of the bounce, as determined by SES. Can be one of <code>UNDETERMINED</code>, <code>TRANSIENT</code>, or <code>PERMANENT</code></p>
    pub fn get_bounce_type(&self) -> &::std::option::Option<crate::types::BounceType> {
        &self.bounce_type
    }
    /// <p>The subtype of the bounce, as determined by SES.</p>
    pub fn bounce_sub_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bounce_sub_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subtype of the bounce, as determined by SES.</p>
    pub fn set_bounce_sub_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bounce_sub_type = input;
        self
    }
    /// <p>The subtype of the bounce, as determined by SES.</p>
    pub fn get_bounce_sub_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.bounce_sub_type
    }
    /// <p>The status code issued by the reporting Message Transfer Authority (MTA). This field only appears if a delivery status notification (DSN) was attached to the bounce and the <code>Diagnostic-Code</code> was provided in the DSN.</p>
    pub fn diagnostic_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.diagnostic_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status code issued by the reporting Message Transfer Authority (MTA). This field only appears if a delivery status notification (DSN) was attached to the bounce and the <code>Diagnostic-Code</code> was provided in the DSN.</p>
    pub fn set_diagnostic_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.diagnostic_code = input;
        self
    }
    /// <p>The status code issued by the reporting Message Transfer Authority (MTA). This field only appears if a delivery status notification (DSN) was attached to the bounce and the <code>Diagnostic-Code</code> was provided in the DSN.</p>
    pub fn get_diagnostic_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.diagnostic_code
    }
    /// Consumes the builder and constructs a [`Bounce`](crate::types::Bounce).
    pub fn build(self) -> crate::types::Bounce {
        crate::types::Bounce {
            bounce_type: self.bounce_type,
            bounce_sub_type: self.bounce_sub_type,
            diagnostic_code: self.diagnostic_code,
        }
    }
}
