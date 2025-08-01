// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateContentInput {
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub knowledge_base_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the content. Each piece of content in a knowledge base must have a unique name. You can retrieve a piece of content using only its knowledge base and its name with the <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_SearchContent.html">SearchContent</a> API.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The title of the content. If not set, the title is equal to the name.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The URI you want to use for the article. If the knowledge base has a templateUri, setting this argument overrides it for this piece of content.</p>
    pub override_link_out_uri: ::std::option::Option<::std::string::String>,
    /// <p>A key/value map to store attributes without affecting tagging or recommendations. For example, when synchronizing data between an external system and Wisdom, you can store an external version identifier as metadata to utilize for determining drift.</p>
    pub metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A pointer to the uploaded asset. This value is returned by <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_StartContentUpload.html">StartContentUpload</a>.</p>
    pub upload_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateContentInput {
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn knowledge_base_id(&self) -> ::std::option::Option<&str> {
        self.knowledge_base_id.as_deref()
    }
    /// <p>The name of the content. Each piece of content in a knowledge base must have a unique name. You can retrieve a piece of content using only its knowledge base and its name with the <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_SearchContent.html">SearchContent</a> API.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The title of the content. If not set, the title is equal to the name.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The URI you want to use for the article. If the knowledge base has a templateUri, setting this argument overrides it for this piece of content.</p>
    pub fn override_link_out_uri(&self) -> ::std::option::Option<&str> {
        self.override_link_out_uri.as_deref()
    }
    /// <p>A key/value map to store attributes without affecting tagging or recommendations. For example, when synchronizing data between an external system and Wisdom, you can store an external version identifier as metadata to utilize for determining drift.</p>
    pub fn metadata(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.metadata.as_ref()
    }
    /// <p>A pointer to the uploaded asset. This value is returned by <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_StartContentUpload.html">StartContentUpload</a>.</p>
    pub fn upload_id(&self) -> ::std::option::Option<&str> {
        self.upload_id.as_deref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateContentInput {
    /// Creates a new builder-style object to manufacture [`CreateContentInput`](crate::operation::create_content::CreateContentInput).
    pub fn builder() -> crate::operation::create_content::builders::CreateContentInputBuilder {
        crate::operation::create_content::builders::CreateContentInputBuilder::default()
    }
}

/// A builder for [`CreateContentInput`](crate::operation::create_content::CreateContentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateContentInputBuilder {
    pub(crate) knowledge_base_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) override_link_out_uri: ::std::option::Option<::std::string::String>,
    pub(crate) metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) upload_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateContentInputBuilder {
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    /// This field is required.
    pub fn knowledge_base_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.knowledge_base_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn set_knowledge_base_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.knowledge_base_id = input;
        self
    }
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn get_knowledge_base_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.knowledge_base_id
    }
    /// <p>The name of the content. Each piece of content in a knowledge base must have a unique name. You can retrieve a piece of content using only its knowledge base and its name with the <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_SearchContent.html">SearchContent</a> API.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the content. Each piece of content in a knowledge base must have a unique name. You can retrieve a piece of content using only its knowledge base and its name with the <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_SearchContent.html">SearchContent</a> API.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the content. Each piece of content in a knowledge base must have a unique name. You can retrieve a piece of content using only its knowledge base and its name with the <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_SearchContent.html">SearchContent</a> API.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The title of the content. If not set, the title is equal to the name.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the content. If not set, the title is equal to the name.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title of the content. If not set, the title is equal to the name.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The URI you want to use for the article. If the knowledge base has a templateUri, setting this argument overrides it for this piece of content.</p>
    pub fn override_link_out_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.override_link_out_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI you want to use for the article. If the knowledge base has a templateUri, setting this argument overrides it for this piece of content.</p>
    pub fn set_override_link_out_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.override_link_out_uri = input;
        self
    }
    /// <p>The URI you want to use for the article. If the knowledge base has a templateUri, setting this argument overrides it for this piece of content.</p>
    pub fn get_override_link_out_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.override_link_out_uri
    }
    /// Adds a key-value pair to `metadata`.
    ///
    /// To override the contents of this collection use [`set_metadata`](Self::set_metadata).
    ///
    /// <p>A key/value map to store attributes without affecting tagging or recommendations. For example, when synchronizing data between an external system and Wisdom, you can store an external version identifier as metadata to utilize for determining drift.</p>
    pub fn metadata(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.metadata.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.metadata = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A key/value map to store attributes without affecting tagging or recommendations. For example, when synchronizing data between an external system and Wisdom, you can store an external version identifier as metadata to utilize for determining drift.</p>
    pub fn set_metadata(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.metadata = input;
        self
    }
    /// <p>A key/value map to store attributes without affecting tagging or recommendations. For example, when synchronizing data between an external system and Wisdom, you can store an external version identifier as metadata to utilize for determining drift.</p>
    pub fn get_metadata(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.metadata
    }
    /// <p>A pointer to the uploaded asset. This value is returned by <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_StartContentUpload.html">StartContentUpload</a>.</p>
    /// This field is required.
    pub fn upload_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.upload_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pointer to the uploaded asset. This value is returned by <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_StartContentUpload.html">StartContentUpload</a>.</p>
    pub fn set_upload_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.upload_id = input;
        self
    }
    /// <p>A pointer to the uploaded asset. This value is returned by <a href="https://docs.aws.amazon.com/wisdom/latest/APIReference/API_StartContentUpload.html">StartContentUpload</a>.</p>
    pub fn get_upload_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.upload_id
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateContentInput`](crate::operation::create_content::CreateContentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_content::CreateContentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_content::CreateContentInput {
            knowledge_base_id: self.knowledge_base_id,
            name: self.name,
            title: self.title,
            override_link_out_uri: self.override_link_out_uri,
            metadata: self.metadata,
            upload_id: self.upload_id,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
