// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A single query result.</p>
/// <p>A query result contains information about a document returned by the query. This includes the original location of the document, a list of attributes assigned to the document, and relevant text from the document that satisfies the query.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueryResultItem {
    /// <p>The unique identifier for the query result item id (<code>Id</code>) and the query result item document id (<code>DocumentId</code>) combined. The value of this field changes with every request, even when you have the same documents.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The type of document within the response. For example, a response could include a question-answer that's relevant to the query.</p>
    pub r#type: ::std::option::Option<crate::types::QueryResultType>,
    /// <p>If the <code>Type</code> of document within the response is <code>ANSWER</code>, then it is either a <code>TABLE</code> answer or <code>TEXT</code> answer. If it's a table answer, a table excerpt is returned in <code>TableExcerpt</code>. If it's a text answer, a text excerpt is returned in <code>DocumentExcerpt</code>.</p>
    pub format: ::std::option::Option<crate::types::QueryResultFormat>,
    /// <p>One or more additional fields/attributes associated with the query result.</p>
    pub additional_attributes: ::std::option::Option<::std::vec::Vec<crate::types::AdditionalResultAttribute>>,
    /// <p>The identifier for the document.</p>
    pub document_id: ::std::option::Option<::std::string::String>,
    /// <p>The title of the document. Contains the text of the title and information for highlighting the relevant terms in the title.</p>
    pub document_title: ::std::option::Option<crate::types::TextWithHighlights>,
    /// <p>An extract of the text in the document. Contains information about highlighting the relevant terms in the excerpt.</p>
    pub document_excerpt: ::std::option::Option<crate::types::TextWithHighlights>,
    /// <p>The URI of the original location of the document.</p>
    pub document_uri: ::std::option::Option<::std::string::String>,
    /// <p>An array of document fields/attributes assigned to a document in the search results. For example, the document author (<code>_author</code>) or the source URI (<code>_source_uri</code>) of the document.</p>
    pub document_attributes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>,
    /// <p>Indicates the confidence level of Amazon Kendra providing a relevant result for the query. Each result is placed into a bin that indicates the confidence, <code>VERY_HIGH</code>, <code>HIGH</code>, <code>MEDIUM</code> and <code>LOW</code>. You can use the score to determine if a response meets the confidence needed for your application.</p>
    /// <p>The field is only set to <code>LOW</code> when the <code>Type</code> field is set to <code>DOCUMENT</code> and Amazon Kendra is not confident that the result is relevant to the query.</p>
    pub score_attributes: ::std::option::Option<crate::types::ScoreAttributes>,
    /// <p>A token that identifies a particular result from a particular query. Use this token to provide click-through feedback for the result. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/submitting-feedback.html">Submitting feedback</a>.</p>
    pub feedback_token: ::std::option::Option<::std::string::String>,
    /// <p>An excerpt from a table within a document.</p>
    pub table_excerpt: ::std::option::Option<crate::types::TableExcerpt>,
    /// <p>Provides details about a collapsed group of search results.</p>
    pub collapsed_result_detail: ::std::option::Option<crate::types::CollapsedResultDetail>,
}
impl QueryResultItem {
    /// <p>The unique identifier for the query result item id (<code>Id</code>) and the query result item document id (<code>DocumentId</code>) combined. The value of this field changes with every request, even when you have the same documents.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The type of document within the response. For example, a response could include a question-answer that's relevant to the query.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::QueryResultType> {
        self.r#type.as_ref()
    }
    /// <p>If the <code>Type</code> of document within the response is <code>ANSWER</code>, then it is either a <code>TABLE</code> answer or <code>TEXT</code> answer. If it's a table answer, a table excerpt is returned in <code>TableExcerpt</code>. If it's a text answer, a text excerpt is returned in <code>DocumentExcerpt</code>.</p>
    pub fn format(&self) -> ::std::option::Option<&crate::types::QueryResultFormat> {
        self.format.as_ref()
    }
    /// <p>One or more additional fields/attributes associated with the query result.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_attributes.is_none()`.
    pub fn additional_attributes(&self) -> &[crate::types::AdditionalResultAttribute] {
        self.additional_attributes.as_deref().unwrap_or_default()
    }
    /// <p>The identifier for the document.</p>
    pub fn document_id(&self) -> ::std::option::Option<&str> {
        self.document_id.as_deref()
    }
    /// <p>The title of the document. Contains the text of the title and information for highlighting the relevant terms in the title.</p>
    pub fn document_title(&self) -> ::std::option::Option<&crate::types::TextWithHighlights> {
        self.document_title.as_ref()
    }
    /// <p>An extract of the text in the document. Contains information about highlighting the relevant terms in the excerpt.</p>
    pub fn document_excerpt(&self) -> ::std::option::Option<&crate::types::TextWithHighlights> {
        self.document_excerpt.as_ref()
    }
    /// <p>The URI of the original location of the document.</p>
    pub fn document_uri(&self) -> ::std::option::Option<&str> {
        self.document_uri.as_deref()
    }
    /// <p>An array of document fields/attributes assigned to a document in the search results. For example, the document author (<code>_author</code>) or the source URI (<code>_source_uri</code>) of the document.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.document_attributes.is_none()`.
    pub fn document_attributes(&self) -> &[crate::types::DocumentAttribute] {
        self.document_attributes.as_deref().unwrap_or_default()
    }
    /// <p>Indicates the confidence level of Amazon Kendra providing a relevant result for the query. Each result is placed into a bin that indicates the confidence, <code>VERY_HIGH</code>, <code>HIGH</code>, <code>MEDIUM</code> and <code>LOW</code>. You can use the score to determine if a response meets the confidence needed for your application.</p>
    /// <p>The field is only set to <code>LOW</code> when the <code>Type</code> field is set to <code>DOCUMENT</code> and Amazon Kendra is not confident that the result is relevant to the query.</p>
    pub fn score_attributes(&self) -> ::std::option::Option<&crate::types::ScoreAttributes> {
        self.score_attributes.as_ref()
    }
    /// <p>A token that identifies a particular result from a particular query. Use this token to provide click-through feedback for the result. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/submitting-feedback.html">Submitting feedback</a>.</p>
    pub fn feedback_token(&self) -> ::std::option::Option<&str> {
        self.feedback_token.as_deref()
    }
    /// <p>An excerpt from a table within a document.</p>
    pub fn table_excerpt(&self) -> ::std::option::Option<&crate::types::TableExcerpt> {
        self.table_excerpt.as_ref()
    }
    /// <p>Provides details about a collapsed group of search results.</p>
    pub fn collapsed_result_detail(&self) -> ::std::option::Option<&crate::types::CollapsedResultDetail> {
        self.collapsed_result_detail.as_ref()
    }
}
impl QueryResultItem {
    /// Creates a new builder-style object to manufacture [`QueryResultItem`](crate::types::QueryResultItem).
    pub fn builder() -> crate::types::builders::QueryResultItemBuilder {
        crate::types::builders::QueryResultItemBuilder::default()
    }
}

/// A builder for [`QueryResultItem`](crate::types::QueryResultItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueryResultItemBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::QueryResultType>,
    pub(crate) format: ::std::option::Option<crate::types::QueryResultFormat>,
    pub(crate) additional_attributes: ::std::option::Option<::std::vec::Vec<crate::types::AdditionalResultAttribute>>,
    pub(crate) document_id: ::std::option::Option<::std::string::String>,
    pub(crate) document_title: ::std::option::Option<crate::types::TextWithHighlights>,
    pub(crate) document_excerpt: ::std::option::Option<crate::types::TextWithHighlights>,
    pub(crate) document_uri: ::std::option::Option<::std::string::String>,
    pub(crate) document_attributes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>,
    pub(crate) score_attributes: ::std::option::Option<crate::types::ScoreAttributes>,
    pub(crate) feedback_token: ::std::option::Option<::std::string::String>,
    pub(crate) table_excerpt: ::std::option::Option<crate::types::TableExcerpt>,
    pub(crate) collapsed_result_detail: ::std::option::Option<crate::types::CollapsedResultDetail>,
}
impl QueryResultItemBuilder {
    /// <p>The unique identifier for the query result item id (<code>Id</code>) and the query result item document id (<code>DocumentId</code>) combined. The value of this field changes with every request, even when you have the same documents.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the query result item id (<code>Id</code>) and the query result item document id (<code>DocumentId</code>) combined. The value of this field changes with every request, even when you have the same documents.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the query result item id (<code>Id</code>) and the query result item document id (<code>DocumentId</code>) combined. The value of this field changes with every request, even when you have the same documents.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The type of document within the response. For example, a response could include a question-answer that's relevant to the query.</p>
    pub fn r#type(mut self, input: crate::types::QueryResultType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of document within the response. For example, a response could include a question-answer that's relevant to the query.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::QueryResultType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of document within the response. For example, a response could include a question-answer that's relevant to the query.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::QueryResultType> {
        &self.r#type
    }
    /// <p>If the <code>Type</code> of document within the response is <code>ANSWER</code>, then it is either a <code>TABLE</code> answer or <code>TEXT</code> answer. If it's a table answer, a table excerpt is returned in <code>TableExcerpt</code>. If it's a text answer, a text excerpt is returned in <code>DocumentExcerpt</code>.</p>
    pub fn format(mut self, input: crate::types::QueryResultFormat) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the <code>Type</code> of document within the response is <code>ANSWER</code>, then it is either a <code>TABLE</code> answer or <code>TEXT</code> answer. If it's a table answer, a table excerpt is returned in <code>TableExcerpt</code>. If it's a text answer, a text excerpt is returned in <code>DocumentExcerpt</code>.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::QueryResultFormat>) -> Self {
        self.format = input;
        self
    }
    /// <p>If the <code>Type</code> of document within the response is <code>ANSWER</code>, then it is either a <code>TABLE</code> answer or <code>TEXT</code> answer. If it's a table answer, a table excerpt is returned in <code>TableExcerpt</code>. If it's a text answer, a text excerpt is returned in <code>DocumentExcerpt</code>.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::QueryResultFormat> {
        &self.format
    }
    /// Appends an item to `additional_attributes`.
    ///
    /// To override the contents of this collection use [`set_additional_attributes`](Self::set_additional_attributes).
    ///
    /// <p>One or more additional fields/attributes associated with the query result.</p>
    pub fn additional_attributes(mut self, input: crate::types::AdditionalResultAttribute) -> Self {
        let mut v = self.additional_attributes.unwrap_or_default();
        v.push(input);
        self.additional_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more additional fields/attributes associated with the query result.</p>
    pub fn set_additional_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AdditionalResultAttribute>>) -> Self {
        self.additional_attributes = input;
        self
    }
    /// <p>One or more additional fields/attributes associated with the query result.</p>
    pub fn get_additional_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AdditionalResultAttribute>> {
        &self.additional_attributes
    }
    /// <p>The identifier for the document.</p>
    pub fn document_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the document.</p>
    pub fn set_document_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_id = input;
        self
    }
    /// <p>The identifier for the document.</p>
    pub fn get_document_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_id
    }
    /// <p>The title of the document. Contains the text of the title and information for highlighting the relevant terms in the title.</p>
    pub fn document_title(mut self, input: crate::types::TextWithHighlights) -> Self {
        self.document_title = ::std::option::Option::Some(input);
        self
    }
    /// <p>The title of the document. Contains the text of the title and information for highlighting the relevant terms in the title.</p>
    pub fn set_document_title(mut self, input: ::std::option::Option<crate::types::TextWithHighlights>) -> Self {
        self.document_title = input;
        self
    }
    /// <p>The title of the document. Contains the text of the title and information for highlighting the relevant terms in the title.</p>
    pub fn get_document_title(&self) -> &::std::option::Option<crate::types::TextWithHighlights> {
        &self.document_title
    }
    /// <p>An extract of the text in the document. Contains information about highlighting the relevant terms in the excerpt.</p>
    pub fn document_excerpt(mut self, input: crate::types::TextWithHighlights) -> Self {
        self.document_excerpt = ::std::option::Option::Some(input);
        self
    }
    /// <p>An extract of the text in the document. Contains information about highlighting the relevant terms in the excerpt.</p>
    pub fn set_document_excerpt(mut self, input: ::std::option::Option<crate::types::TextWithHighlights>) -> Self {
        self.document_excerpt = input;
        self
    }
    /// <p>An extract of the text in the document. Contains information about highlighting the relevant terms in the excerpt.</p>
    pub fn get_document_excerpt(&self) -> &::std::option::Option<crate::types::TextWithHighlights> {
        &self.document_excerpt
    }
    /// <p>The URI of the original location of the document.</p>
    pub fn document_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI of the original location of the document.</p>
    pub fn set_document_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_uri = input;
        self
    }
    /// <p>The URI of the original location of the document.</p>
    pub fn get_document_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_uri
    }
    /// Appends an item to `document_attributes`.
    ///
    /// To override the contents of this collection use [`set_document_attributes`](Self::set_document_attributes).
    ///
    /// <p>An array of document fields/attributes assigned to a document in the search results. For example, the document author (<code>_author</code>) or the source URI (<code>_source_uri</code>) of the document.</p>
    pub fn document_attributes(mut self, input: crate::types::DocumentAttribute) -> Self {
        let mut v = self.document_attributes.unwrap_or_default();
        v.push(input);
        self.document_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of document fields/attributes assigned to a document in the search results. For example, the document author (<code>_author</code>) or the source URI (<code>_source_uri</code>) of the document.</p>
    pub fn set_document_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>) -> Self {
        self.document_attributes = input;
        self
    }
    /// <p>An array of document fields/attributes assigned to a document in the search results. For example, the document author (<code>_author</code>) or the source URI (<code>_source_uri</code>) of the document.</p>
    pub fn get_document_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>> {
        &self.document_attributes
    }
    /// <p>Indicates the confidence level of Amazon Kendra providing a relevant result for the query. Each result is placed into a bin that indicates the confidence, <code>VERY_HIGH</code>, <code>HIGH</code>, <code>MEDIUM</code> and <code>LOW</code>. You can use the score to determine if a response meets the confidence needed for your application.</p>
    /// <p>The field is only set to <code>LOW</code> when the <code>Type</code> field is set to <code>DOCUMENT</code> and Amazon Kendra is not confident that the result is relevant to the query.</p>
    pub fn score_attributes(mut self, input: crate::types::ScoreAttributes) -> Self {
        self.score_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the confidence level of Amazon Kendra providing a relevant result for the query. Each result is placed into a bin that indicates the confidence, <code>VERY_HIGH</code>, <code>HIGH</code>, <code>MEDIUM</code> and <code>LOW</code>. You can use the score to determine if a response meets the confidence needed for your application.</p>
    /// <p>The field is only set to <code>LOW</code> when the <code>Type</code> field is set to <code>DOCUMENT</code> and Amazon Kendra is not confident that the result is relevant to the query.</p>
    pub fn set_score_attributes(mut self, input: ::std::option::Option<crate::types::ScoreAttributes>) -> Self {
        self.score_attributes = input;
        self
    }
    /// <p>Indicates the confidence level of Amazon Kendra providing a relevant result for the query. Each result is placed into a bin that indicates the confidence, <code>VERY_HIGH</code>, <code>HIGH</code>, <code>MEDIUM</code> and <code>LOW</code>. You can use the score to determine if a response meets the confidence needed for your application.</p>
    /// <p>The field is only set to <code>LOW</code> when the <code>Type</code> field is set to <code>DOCUMENT</code> and Amazon Kendra is not confident that the result is relevant to the query.</p>
    pub fn get_score_attributes(&self) -> &::std::option::Option<crate::types::ScoreAttributes> {
        &self.score_attributes
    }
    /// <p>A token that identifies a particular result from a particular query. Use this token to provide click-through feedback for the result. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/submitting-feedback.html">Submitting feedback</a>.</p>
    pub fn feedback_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feedback_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that identifies a particular result from a particular query. Use this token to provide click-through feedback for the result. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/submitting-feedback.html">Submitting feedback</a>.</p>
    pub fn set_feedback_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feedback_token = input;
        self
    }
    /// <p>A token that identifies a particular result from a particular query. Use this token to provide click-through feedback for the result. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/submitting-feedback.html">Submitting feedback</a>.</p>
    pub fn get_feedback_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.feedback_token
    }
    /// <p>An excerpt from a table within a document.</p>
    pub fn table_excerpt(mut self, input: crate::types::TableExcerpt) -> Self {
        self.table_excerpt = ::std::option::Option::Some(input);
        self
    }
    /// <p>An excerpt from a table within a document.</p>
    pub fn set_table_excerpt(mut self, input: ::std::option::Option<crate::types::TableExcerpt>) -> Self {
        self.table_excerpt = input;
        self
    }
    /// <p>An excerpt from a table within a document.</p>
    pub fn get_table_excerpt(&self) -> &::std::option::Option<crate::types::TableExcerpt> {
        &self.table_excerpt
    }
    /// <p>Provides details about a collapsed group of search results.</p>
    pub fn collapsed_result_detail(mut self, input: crate::types::CollapsedResultDetail) -> Self {
        self.collapsed_result_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides details about a collapsed group of search results.</p>
    pub fn set_collapsed_result_detail(mut self, input: ::std::option::Option<crate::types::CollapsedResultDetail>) -> Self {
        self.collapsed_result_detail = input;
        self
    }
    /// <p>Provides details about a collapsed group of search results.</p>
    pub fn get_collapsed_result_detail(&self) -> &::std::option::Option<crate::types::CollapsedResultDetail> {
        &self.collapsed_result_detail
    }
    /// Consumes the builder and constructs a [`QueryResultItem`](crate::types::QueryResultItem).
    pub fn build(self) -> crate::types::QueryResultItem {
        crate::types::QueryResultItem {
            id: self.id,
            r#type: self.r#type,
            format: self.format,
            additional_attributes: self.additional_attributes,
            document_id: self.document_id,
            document_title: self.document_title,
            document_excerpt: self.document_excerpt,
            document_uri: self.document_uri,
            document_attributes: self.document_attributes,
            score_attributes: self.score_attributes,
            feedback_token: self.feedback_token,
            table_excerpt: self.table_excerpt,
            collapsed_result_detail: self.collapsed_result_detail,
        }
    }
}
