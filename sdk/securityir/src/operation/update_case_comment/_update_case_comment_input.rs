// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateCaseCommentInput {
    /// <p>Required element for UpdateCaseComment to identify the case ID containing the comment to be updated.</p>
    pub case_id: ::std::option::Option<::std::string::String>,
    /// <p>Required element for UpdateCaseComment to identify the case ID to be updated.</p>
    pub comment_id: ::std::option::Option<::std::string::String>,
    /// <p>Required element for UpdateCaseComment to identify the content for the comment to be updated.</p>
    pub body: ::std::option::Option<::std::string::String>,
}
impl UpdateCaseCommentInput {
    /// <p>Required element for UpdateCaseComment to identify the case ID containing the comment to be updated.</p>
    pub fn case_id(&self) -> ::std::option::Option<&str> {
        self.case_id.as_deref()
    }
    /// <p>Required element for UpdateCaseComment to identify the case ID to be updated.</p>
    pub fn comment_id(&self) -> ::std::option::Option<&str> {
        self.comment_id.as_deref()
    }
    /// <p>Required element for UpdateCaseComment to identify the content for the comment to be updated.</p>
    pub fn body(&self) -> ::std::option::Option<&str> {
        self.body.as_deref()
    }
}
impl ::std::fmt::Debug for UpdateCaseCommentInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateCaseCommentInput");
        formatter.field("case_id", &self.case_id);
        formatter.field("comment_id", &self.comment_id);
        formatter.field("body", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl UpdateCaseCommentInput {
    /// Creates a new builder-style object to manufacture [`UpdateCaseCommentInput`](crate::operation::update_case_comment::UpdateCaseCommentInput).
    pub fn builder() -> crate::operation::update_case_comment::builders::UpdateCaseCommentInputBuilder {
        crate::operation::update_case_comment::builders::UpdateCaseCommentInputBuilder::default()
    }
}

/// A builder for [`UpdateCaseCommentInput`](crate::operation::update_case_comment::UpdateCaseCommentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateCaseCommentInputBuilder {
    pub(crate) case_id: ::std::option::Option<::std::string::String>,
    pub(crate) comment_id: ::std::option::Option<::std::string::String>,
    pub(crate) body: ::std::option::Option<::std::string::String>,
}
impl UpdateCaseCommentInputBuilder {
    /// <p>Required element for UpdateCaseComment to identify the case ID containing the comment to be updated.</p>
    /// This field is required.
    pub fn case_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.case_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required element for UpdateCaseComment to identify the case ID containing the comment to be updated.</p>
    pub fn set_case_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.case_id = input;
        self
    }
    /// <p>Required element for UpdateCaseComment to identify the case ID containing the comment to be updated.</p>
    pub fn get_case_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.case_id
    }
    /// <p>Required element for UpdateCaseComment to identify the case ID to be updated.</p>
    /// This field is required.
    pub fn comment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.comment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required element for UpdateCaseComment to identify the case ID to be updated.</p>
    pub fn set_comment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.comment_id = input;
        self
    }
    /// <p>Required element for UpdateCaseComment to identify the case ID to be updated.</p>
    pub fn get_comment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.comment_id
    }
    /// <p>Required element for UpdateCaseComment to identify the content for the comment to be updated.</p>
    /// This field is required.
    pub fn body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required element for UpdateCaseComment to identify the content for the comment to be updated.</p>
    pub fn set_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.body = input;
        self
    }
    /// <p>Required element for UpdateCaseComment to identify the content for the comment to be updated.</p>
    pub fn get_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.body
    }
    /// Consumes the builder and constructs a [`UpdateCaseCommentInput`](crate::operation::update_case_comment::UpdateCaseCommentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_case_comment::UpdateCaseCommentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_case_comment::UpdateCaseCommentInput {
            case_id: self.case_id,
            comment_id: self.comment_id,
            body: self.body,
        })
    }
}
impl ::std::fmt::Debug for UpdateCaseCommentInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateCaseCommentInputBuilder");
        formatter.field("case_id", &self.case_id);
        formatter.field("comment_id", &self.comment_id);
        formatter.field("body", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
