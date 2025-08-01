// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ClassifyDocumentOutput {
    /// <p>The classes used by the document being analyzed. These are used for models trained in multi-class mode. Individual classes are mutually exclusive and each document is expected to have only a single class assigned to it. For example, an animal can be a dog or a cat, but not both at the same time.</p>
    /// <p>For prompt safety classification, the response includes only two classes (SAFE_PROMPT and UNSAFE_PROMPT), along with a confidence score for each class. The value range of the score is zero to one, where one is the highest confidence.</p>
    pub classes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentClass>>,
    /// <p>The labels used in the document being analyzed. These are used for multi-label trained models. Individual labels represent different categories that are related in some manner and are not mutually exclusive. For example, a movie can be just an action movie, or it can be an action movie, a science fiction movie, and a comedy, all at the same time.</p>
    pub labels: ::std::option::Option<::std::vec::Vec<crate::types::DocumentLabel>>,
    /// <p>Extraction information about the document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub document_metadata: ::std::option::Option<crate::types::DocumentMetadata>,
    /// <p>The document type for each page in the input document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub document_type: ::std::option::Option<::std::vec::Vec<crate::types::DocumentTypeListItem>>,
    /// <p>Page-level errors that the system detected while processing the input document. The field is empty if the system encountered no errors.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::ErrorsListItem>>,
    /// <p>Warnings detected while processing the input document. The response includes a warning if there is a mismatch between the input document type and the model type associated with the endpoint that you specified. The response can also include warnings for individual pages that have a mismatch.</p>
    /// <p>The field is empty if the system generated no warnings.</p>
    pub warnings: ::std::option::Option<::std::vec::Vec<crate::types::WarningsListItem>>,
    _request_id: Option<String>,
}
impl ClassifyDocumentOutput {
    /// <p>The classes used by the document being analyzed. These are used for models trained in multi-class mode. Individual classes are mutually exclusive and each document is expected to have only a single class assigned to it. For example, an animal can be a dog or a cat, but not both at the same time.</p>
    /// <p>For prompt safety classification, the response includes only two classes (SAFE_PROMPT and UNSAFE_PROMPT), along with a confidence score for each class. The value range of the score is zero to one, where one is the highest confidence.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.classes.is_none()`.
    pub fn classes(&self) -> &[crate::types::DocumentClass] {
        self.classes.as_deref().unwrap_or_default()
    }
    /// <p>The labels used in the document being analyzed. These are used for multi-label trained models. Individual labels represent different categories that are related in some manner and are not mutually exclusive. For example, a movie can be just an action movie, or it can be an action movie, a science fiction movie, and a comedy, all at the same time.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.labels.is_none()`.
    pub fn labels(&self) -> &[crate::types::DocumentLabel] {
        self.labels.as_deref().unwrap_or_default()
    }
    /// <p>Extraction information about the document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub fn document_metadata(&self) -> ::std::option::Option<&crate::types::DocumentMetadata> {
        self.document_metadata.as_ref()
    }
    /// <p>The document type for each page in the input document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.document_type.is_none()`.
    pub fn document_type(&self) -> &[crate::types::DocumentTypeListItem] {
        self.document_type.as_deref().unwrap_or_default()
    }
    /// <p>Page-level errors that the system detected while processing the input document. The field is empty if the system encountered no errors.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::ErrorsListItem] {
        self.errors.as_deref().unwrap_or_default()
    }
    /// <p>Warnings detected while processing the input document. The response includes a warning if there is a mismatch between the input document type and the model type associated with the endpoint that you specified. The response can also include warnings for individual pages that have a mismatch.</p>
    /// <p>The field is empty if the system generated no warnings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.warnings.is_none()`.
    pub fn warnings(&self) -> &[crate::types::WarningsListItem] {
        self.warnings.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for ClassifyDocumentOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ClassifyDocumentOutput");
        formatter.field("classes", &"*** Sensitive Data Redacted ***");
        formatter.field("labels", &"*** Sensitive Data Redacted ***");
        formatter.field("document_metadata", &"*** Sensitive Data Redacted ***");
        formatter.field("document_type", &"*** Sensitive Data Redacted ***");
        formatter.field("errors", &"*** Sensitive Data Redacted ***");
        formatter.field("warnings", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for ClassifyDocumentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ClassifyDocumentOutput {
    /// Creates a new builder-style object to manufacture [`ClassifyDocumentOutput`](crate::operation::classify_document::ClassifyDocumentOutput).
    pub fn builder() -> crate::operation::classify_document::builders::ClassifyDocumentOutputBuilder {
        crate::operation::classify_document::builders::ClassifyDocumentOutputBuilder::default()
    }
}

/// A builder for [`ClassifyDocumentOutput`](crate::operation::classify_document::ClassifyDocumentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ClassifyDocumentOutputBuilder {
    pub(crate) classes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentClass>>,
    pub(crate) labels: ::std::option::Option<::std::vec::Vec<crate::types::DocumentLabel>>,
    pub(crate) document_metadata: ::std::option::Option<crate::types::DocumentMetadata>,
    pub(crate) document_type: ::std::option::Option<::std::vec::Vec<crate::types::DocumentTypeListItem>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::ErrorsListItem>>,
    pub(crate) warnings: ::std::option::Option<::std::vec::Vec<crate::types::WarningsListItem>>,
    _request_id: Option<String>,
}
impl ClassifyDocumentOutputBuilder {
    /// Appends an item to `classes`.
    ///
    /// To override the contents of this collection use [`set_classes`](Self::set_classes).
    ///
    /// <p>The classes used by the document being analyzed. These are used for models trained in multi-class mode. Individual classes are mutually exclusive and each document is expected to have only a single class assigned to it. For example, an animal can be a dog or a cat, but not both at the same time.</p>
    /// <p>For prompt safety classification, the response includes only two classes (SAFE_PROMPT and UNSAFE_PROMPT), along with a confidence score for each class. The value range of the score is zero to one, where one is the highest confidence.</p>
    pub fn classes(mut self, input: crate::types::DocumentClass) -> Self {
        let mut v = self.classes.unwrap_or_default();
        v.push(input);
        self.classes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The classes used by the document being analyzed. These are used for models trained in multi-class mode. Individual classes are mutually exclusive and each document is expected to have only a single class assigned to it. For example, an animal can be a dog or a cat, but not both at the same time.</p>
    /// <p>For prompt safety classification, the response includes only two classes (SAFE_PROMPT and UNSAFE_PROMPT), along with a confidence score for each class. The value range of the score is zero to one, where one is the highest confidence.</p>
    pub fn set_classes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentClass>>) -> Self {
        self.classes = input;
        self
    }
    /// <p>The classes used by the document being analyzed. These are used for models trained in multi-class mode. Individual classes are mutually exclusive and each document is expected to have only a single class assigned to it. For example, an animal can be a dog or a cat, but not both at the same time.</p>
    /// <p>For prompt safety classification, the response includes only two classes (SAFE_PROMPT and UNSAFE_PROMPT), along with a confidence score for each class. The value range of the score is zero to one, where one is the highest confidence.</p>
    pub fn get_classes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentClass>> {
        &self.classes
    }
    /// Appends an item to `labels`.
    ///
    /// To override the contents of this collection use [`set_labels`](Self::set_labels).
    ///
    /// <p>The labels used in the document being analyzed. These are used for multi-label trained models. Individual labels represent different categories that are related in some manner and are not mutually exclusive. For example, a movie can be just an action movie, or it can be an action movie, a science fiction movie, and a comedy, all at the same time.</p>
    pub fn labels(mut self, input: crate::types::DocumentLabel) -> Self {
        let mut v = self.labels.unwrap_or_default();
        v.push(input);
        self.labels = ::std::option::Option::Some(v);
        self
    }
    /// <p>The labels used in the document being analyzed. These are used for multi-label trained models. Individual labels represent different categories that are related in some manner and are not mutually exclusive. For example, a movie can be just an action movie, or it can be an action movie, a science fiction movie, and a comedy, all at the same time.</p>
    pub fn set_labels(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentLabel>>) -> Self {
        self.labels = input;
        self
    }
    /// <p>The labels used in the document being analyzed. These are used for multi-label trained models. Individual labels represent different categories that are related in some manner and are not mutually exclusive. For example, a movie can be just an action movie, or it can be an action movie, a science fiction movie, and a comedy, all at the same time.</p>
    pub fn get_labels(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentLabel>> {
        &self.labels
    }
    /// <p>Extraction information about the document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub fn document_metadata(mut self, input: crate::types::DocumentMetadata) -> Self {
        self.document_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>Extraction information about the document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub fn set_document_metadata(mut self, input: ::std::option::Option<crate::types::DocumentMetadata>) -> Self {
        self.document_metadata = input;
        self
    }
    /// <p>Extraction information about the document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub fn get_document_metadata(&self) -> &::std::option::Option<crate::types::DocumentMetadata> {
        &self.document_metadata
    }
    /// Appends an item to `document_type`.
    ///
    /// To override the contents of this collection use [`set_document_type`](Self::set_document_type).
    ///
    /// <p>The document type for each page in the input document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub fn document_type(mut self, input: crate::types::DocumentTypeListItem) -> Self {
        let mut v = self.document_type.unwrap_or_default();
        v.push(input);
        self.document_type = ::std::option::Option::Some(v);
        self
    }
    /// <p>The document type for each page in the input document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub fn set_document_type(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentTypeListItem>>) -> Self {
        self.document_type = input;
        self
    }
    /// <p>The document type for each page in the input document. This field is present in the response only if your request includes the <code>Byte</code> parameter.</p>
    pub fn get_document_type(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentTypeListItem>> {
        &self.document_type
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>Page-level errors that the system detected while processing the input document. The field is empty if the system encountered no errors.</p>
    pub fn errors(mut self, input: crate::types::ErrorsListItem) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Page-level errors that the system detected while processing the input document. The field is empty if the system encountered no errors.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ErrorsListItem>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>Page-level errors that the system detected while processing the input document. The field is empty if the system encountered no errors.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ErrorsListItem>> {
        &self.errors
    }
    /// Appends an item to `warnings`.
    ///
    /// To override the contents of this collection use [`set_warnings`](Self::set_warnings).
    ///
    /// <p>Warnings detected while processing the input document. The response includes a warning if there is a mismatch between the input document type and the model type associated with the endpoint that you specified. The response can also include warnings for individual pages that have a mismatch.</p>
    /// <p>The field is empty if the system generated no warnings.</p>
    pub fn warnings(mut self, input: crate::types::WarningsListItem) -> Self {
        let mut v = self.warnings.unwrap_or_default();
        v.push(input);
        self.warnings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Warnings detected while processing the input document. The response includes a warning if there is a mismatch between the input document type and the model type associated with the endpoint that you specified. The response can also include warnings for individual pages that have a mismatch.</p>
    /// <p>The field is empty if the system generated no warnings.</p>
    pub fn set_warnings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WarningsListItem>>) -> Self {
        self.warnings = input;
        self
    }
    /// <p>Warnings detected while processing the input document. The response includes a warning if there is a mismatch between the input document type and the model type associated with the endpoint that you specified. The response can also include warnings for individual pages that have a mismatch.</p>
    /// <p>The field is empty if the system generated no warnings.</p>
    pub fn get_warnings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WarningsListItem>> {
        &self.warnings
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ClassifyDocumentOutput`](crate::operation::classify_document::ClassifyDocumentOutput).
    pub fn build(self) -> crate::operation::classify_document::ClassifyDocumentOutput {
        crate::operation::classify_document::ClassifyDocumentOutput {
            classes: self.classes,
            labels: self.labels,
            document_metadata: self.document_metadata,
            document_type: self.document_type,
            errors: self.errors,
            warnings: self.warnings,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for ClassifyDocumentOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ClassifyDocumentOutputBuilder");
        formatter.field("classes", &"*** Sensitive Data Redacted ***");
        formatter.field("labels", &"*** Sensitive Data Redacted ***");
        formatter.field("document_metadata", &"*** Sensitive Data Redacted ***");
        formatter.field("document_type", &"*** Sensitive Data Redacted ***");
        formatter.field("errors", &"*** Sensitive Data Redacted ***");
        formatter.field("warnings", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
