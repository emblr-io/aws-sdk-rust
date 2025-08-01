// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRdfGraphSummaryInput {
    /// <p>Mode can take one of two values: <code>BASIC</code> (the default), and <code>DETAILED</code>.</p>
    pub mode: ::std::option::Option<crate::types::GraphSummaryType>,
}
impl GetRdfGraphSummaryInput {
    /// <p>Mode can take one of two values: <code>BASIC</code> (the default), and <code>DETAILED</code>.</p>
    pub fn mode(&self) -> ::std::option::Option<&crate::types::GraphSummaryType> {
        self.mode.as_ref()
    }
}
impl GetRdfGraphSummaryInput {
    /// Creates a new builder-style object to manufacture [`GetRdfGraphSummaryInput`](crate::operation::get_rdf_graph_summary::GetRdfGraphSummaryInput).
    pub fn builder() -> crate::operation::get_rdf_graph_summary::builders::GetRdfGraphSummaryInputBuilder {
        crate::operation::get_rdf_graph_summary::builders::GetRdfGraphSummaryInputBuilder::default()
    }
}

/// A builder for [`GetRdfGraphSummaryInput`](crate::operation::get_rdf_graph_summary::GetRdfGraphSummaryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRdfGraphSummaryInputBuilder {
    pub(crate) mode: ::std::option::Option<crate::types::GraphSummaryType>,
}
impl GetRdfGraphSummaryInputBuilder {
    /// <p>Mode can take one of two values: <code>BASIC</code> (the default), and <code>DETAILED</code>.</p>
    pub fn mode(mut self, input: crate::types::GraphSummaryType) -> Self {
        self.mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Mode can take one of two values: <code>BASIC</code> (the default), and <code>DETAILED</code>.</p>
    pub fn set_mode(mut self, input: ::std::option::Option<crate::types::GraphSummaryType>) -> Self {
        self.mode = input;
        self
    }
    /// <p>Mode can take one of two values: <code>BASIC</code> (the default), and <code>DETAILED</code>.</p>
    pub fn get_mode(&self) -> &::std::option::Option<crate::types::GraphSummaryType> {
        &self.mode
    }
    /// Consumes the builder and constructs a [`GetRdfGraphSummaryInput`](crate::operation::get_rdf_graph_summary::GetRdfGraphSummaryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_rdf_graph_summary::GetRdfGraphSummaryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_rdf_graph_summary::GetRdfGraphSummaryInput { mode: self.mode })
    }
}
