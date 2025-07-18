// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides detailed context information for an Engagement. This structure allows for specifying the type of context and its associated payload.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EngagementContextDetails {
    /// <p>Specifies the type of Engagement context. Valid values are "CustomerProject" or "Document", indicating whether the context relates to a customer project or a document respectively.</p>
    pub r#type: crate::types::EngagementContextType,
    /// <p>Contains the specific details of the Engagement context. The structure of this payload varies depending on the Type field.</p>
    pub payload: ::std::option::Option<crate::types::EngagementContextPayload>,
}
impl EngagementContextDetails {
    /// <p>Specifies the type of Engagement context. Valid values are "CustomerProject" or "Document", indicating whether the context relates to a customer project or a document respectively.</p>
    pub fn r#type(&self) -> &crate::types::EngagementContextType {
        &self.r#type
    }
    /// <p>Contains the specific details of the Engagement context. The structure of this payload varies depending on the Type field.</p>
    pub fn payload(&self) -> ::std::option::Option<&crate::types::EngagementContextPayload> {
        self.payload.as_ref()
    }
}
impl EngagementContextDetails {
    /// Creates a new builder-style object to manufacture [`EngagementContextDetails`](crate::types::EngagementContextDetails).
    pub fn builder() -> crate::types::builders::EngagementContextDetailsBuilder {
        crate::types::builders::EngagementContextDetailsBuilder::default()
    }
}

/// A builder for [`EngagementContextDetails`](crate::types::EngagementContextDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EngagementContextDetailsBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::EngagementContextType>,
    pub(crate) payload: ::std::option::Option<crate::types::EngagementContextPayload>,
}
impl EngagementContextDetailsBuilder {
    /// <p>Specifies the type of Engagement context. Valid values are "CustomerProject" or "Document", indicating whether the context relates to a customer project or a document respectively.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::EngagementContextType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of Engagement context. Valid values are "CustomerProject" or "Document", indicating whether the context relates to a customer project or a document respectively.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::EngagementContextType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Specifies the type of Engagement context. Valid values are "CustomerProject" or "Document", indicating whether the context relates to a customer project or a document respectively.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::EngagementContextType> {
        &self.r#type
    }
    /// <p>Contains the specific details of the Engagement context. The structure of this payload varies depending on the Type field.</p>
    pub fn payload(mut self, input: crate::types::EngagementContextPayload) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the specific details of the Engagement context. The structure of this payload varies depending on the Type field.</p>
    pub fn set_payload(mut self, input: ::std::option::Option<crate::types::EngagementContextPayload>) -> Self {
        self.payload = input;
        self
    }
    /// <p>Contains the specific details of the Engagement context. The structure of this payload varies depending on the Type field.</p>
    pub fn get_payload(&self) -> &::std::option::Option<crate::types::EngagementContextPayload> {
        &self.payload
    }
    /// Consumes the builder and constructs a [`EngagementContextDetails`](crate::types::EngagementContextDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::EngagementContextDetailsBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::EngagementContextDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EngagementContextDetails {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building EngagementContextDetails",
                )
            })?,
            payload: self.payload,
        })
    }
}
