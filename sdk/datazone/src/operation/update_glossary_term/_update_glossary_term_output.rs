// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateGlossaryTermOutput {
    /// <p>The identifier of the business glossary term that is to be updated.</p>
    pub id: ::std::string::String,
    /// <p>The identifier of the Amazon DataZone domain in which a business glossary term is to be updated.</p>
    pub domain_id: ::std::string::String,
    /// <p>The identifier of the business glossary in which a term is to be updated.</p>
    pub glossary_id: ::std::string::String,
    /// <p>The name to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub name: ::std::string::String,
    /// <p>The status to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub status: crate::types::GlossaryTermStatus,
    /// <p>The short description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub short_description: ::std::option::Option<::std::string::String>,
    /// <p>The long description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub long_description: ::std::option::Option<::std::string::String>,
    /// <p>The term relations to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub term_relations: ::std::option::Option<crate::types::TermRelations>,
    _request_id: Option<String>,
}
impl UpdateGlossaryTermOutput {
    /// <p>The identifier of the business glossary term that is to be updated.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The identifier of the Amazon DataZone domain in which a business glossary term is to be updated.</p>
    pub fn domain_id(&self) -> &str {
        use std::ops::Deref;
        self.domain_id.deref()
    }
    /// <p>The identifier of the business glossary in which a term is to be updated.</p>
    pub fn glossary_id(&self) -> &str {
        use std::ops::Deref;
        self.glossary_id.deref()
    }
    /// <p>The name to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The status to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn status(&self) -> &crate::types::GlossaryTermStatus {
        &self.status
    }
    /// <p>The short description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn short_description(&self) -> ::std::option::Option<&str> {
        self.short_description.as_deref()
    }
    /// <p>The long description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn long_description(&self) -> ::std::option::Option<&str> {
        self.long_description.as_deref()
    }
    /// <p>The term relations to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn term_relations(&self) -> ::std::option::Option<&crate::types::TermRelations> {
        self.term_relations.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateGlossaryTermOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateGlossaryTermOutput");
        formatter.field("id", &self.id);
        formatter.field("domain_id", &self.domain_id);
        formatter.field("glossary_id", &self.glossary_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("short_description", &"*** Sensitive Data Redacted ***");
        formatter.field("long_description", &"*** Sensitive Data Redacted ***");
        formatter.field("term_relations", &self.term_relations);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for UpdateGlossaryTermOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateGlossaryTermOutput {
    /// Creates a new builder-style object to manufacture [`UpdateGlossaryTermOutput`](crate::operation::update_glossary_term::UpdateGlossaryTermOutput).
    pub fn builder() -> crate::operation::update_glossary_term::builders::UpdateGlossaryTermOutputBuilder {
        crate::operation::update_glossary_term::builders::UpdateGlossaryTermOutputBuilder::default()
    }
}

/// A builder for [`UpdateGlossaryTermOutput`](crate::operation::update_glossary_term::UpdateGlossaryTermOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateGlossaryTermOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) glossary_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::GlossaryTermStatus>,
    pub(crate) short_description: ::std::option::Option<::std::string::String>,
    pub(crate) long_description: ::std::option::Option<::std::string::String>,
    pub(crate) term_relations: ::std::option::Option<crate::types::TermRelations>,
    _request_id: Option<String>,
}
impl UpdateGlossaryTermOutputBuilder {
    /// <p>The identifier of the business glossary term that is to be updated.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the business glossary term that is to be updated.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the business glossary term that is to be updated.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The identifier of the Amazon DataZone domain in which a business glossary term is to be updated.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which a business glossary term is to be updated.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which a business glossary term is to be updated.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The identifier of the business glossary in which a term is to be updated.</p>
    /// This field is required.
    pub fn glossary_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.glossary_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the business glossary in which a term is to be updated.</p>
    pub fn set_glossary_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.glossary_id = input;
        self
    }
    /// <p>The identifier of the business glossary in which a term is to be updated.</p>
    pub fn get_glossary_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.glossary_id
    }
    /// <p>The name to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The status to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::GlossaryTermStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::GlossaryTermStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::GlossaryTermStatus> {
        &self.status
    }
    /// <p>The short description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn short_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.short_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The short description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn set_short_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.short_description = input;
        self
    }
    /// <p>The short description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn get_short_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.short_description
    }
    /// <p>The long description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn long_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.long_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The long description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn set_long_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.long_description = input;
        self
    }
    /// <p>The long description to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn get_long_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.long_description
    }
    /// <p>The term relations to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn term_relations(mut self, input: crate::types::TermRelations) -> Self {
        self.term_relations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The term relations to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn set_term_relations(mut self, input: ::std::option::Option<crate::types::TermRelations>) -> Self {
        self.term_relations = input;
        self
    }
    /// <p>The term relations to be updated as part of the <code>UpdateGlossaryTerm</code> action.</p>
    pub fn get_term_relations(&self) -> &::std::option::Option<crate::types::TermRelations> {
        &self.term_relations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateGlossaryTermOutput`](crate::operation::update_glossary_term::UpdateGlossaryTermOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::update_glossary_term::builders::UpdateGlossaryTermOutputBuilder::id)
    /// - [`domain_id`](crate::operation::update_glossary_term::builders::UpdateGlossaryTermOutputBuilder::domain_id)
    /// - [`glossary_id`](crate::operation::update_glossary_term::builders::UpdateGlossaryTermOutputBuilder::glossary_id)
    /// - [`name`](crate::operation::update_glossary_term::builders::UpdateGlossaryTermOutputBuilder::name)
    /// - [`status`](crate::operation::update_glossary_term::builders::UpdateGlossaryTermOutputBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_glossary_term::UpdateGlossaryTermOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_glossary_term::UpdateGlossaryTermOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building UpdateGlossaryTermOutput",
                )
            })?,
            domain_id: self.domain_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_id",
                    "domain_id was not specified but it is required when building UpdateGlossaryTermOutput",
                )
            })?,
            glossary_id: self.glossary_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "glossary_id",
                    "glossary_id was not specified but it is required when building UpdateGlossaryTermOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building UpdateGlossaryTermOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building UpdateGlossaryTermOutput",
                )
            })?,
            short_description: self.short_description,
            long_description: self.long_description,
            term_relations: self.term_relations,
            _request_id: self._request_id,
        })
    }
}
impl ::std::fmt::Debug for UpdateGlossaryTermOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateGlossaryTermOutputBuilder");
        formatter.field("id", &self.id);
        formatter.field("domain_id", &self.domain_id);
        formatter.field("glossary_id", &self.glossary_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("short_description", &"*** Sensitive Data Redacted ***");
        formatter.field("long_description", &"*** Sensitive Data Redacted ***");
        formatter.field("term_relations", &self.term_relations);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
