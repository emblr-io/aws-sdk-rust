// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteJourneyInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the journey.</p>
    pub journey_id: ::std::option::Option<::std::string::String>,
}
impl DeleteJourneyInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The unique identifier for the journey.</p>
    pub fn journey_id(&self) -> ::std::option::Option<&str> {
        self.journey_id.as_deref()
    }
}
impl DeleteJourneyInput {
    /// Creates a new builder-style object to manufacture [`DeleteJourneyInput`](crate::operation::delete_journey::DeleteJourneyInput).
    pub fn builder() -> crate::operation::delete_journey::builders::DeleteJourneyInputBuilder {
        crate::operation::delete_journey::builders::DeleteJourneyInputBuilder::default()
    }
}

/// A builder for [`DeleteJourneyInput`](crate::operation::delete_journey::DeleteJourneyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteJourneyInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) journey_id: ::std::option::Option<::std::string::String>,
}
impl DeleteJourneyInputBuilder {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The unique identifier for the journey.</p>
    /// This field is required.
    pub fn journey_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.journey_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the journey.</p>
    pub fn set_journey_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.journey_id = input;
        self
    }
    /// <p>The unique identifier for the journey.</p>
    pub fn get_journey_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.journey_id
    }
    /// Consumes the builder and constructs a [`DeleteJourneyInput`](crate::operation::delete_journey::DeleteJourneyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_journey::DeleteJourneyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_journey::DeleteJourneyInput {
            application_id: self.application_id,
            journey_id: self.journey_id,
        })
    }
}
