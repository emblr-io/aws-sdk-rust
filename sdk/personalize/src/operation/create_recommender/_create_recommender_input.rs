// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRecommenderInput {
    /// <p>The name of the recommender.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the destination domain dataset group for the recommender.</p>
    pub dataset_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the recipe that the recommender will use. For a recommender, a recipe is a Domain dataset group use case. Only Domain dataset group use cases can be used to create a recommender. For information about use cases see <a href="https://docs.aws.amazon.com/personalize/latest/dg/domain-use-cases.html">Choosing recommender use cases</a>.</p>
    pub recipe_arn: ::std::option::Option<::std::string::String>,
    /// <p>The configuration details of the recommender.</p>
    pub recommender_config: ::std::option::Option<crate::types::RecommenderConfig>,
    /// <p>A list of <a href="https://docs.aws.amazon.com/personalize/latest/dg/tagging-resources.html">tags</a> to apply to the recommender.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateRecommenderInput {
    /// <p>The name of the recommender.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the destination domain dataset group for the recommender.</p>
    pub fn dataset_group_arn(&self) -> ::std::option::Option<&str> {
        self.dataset_group_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the recipe that the recommender will use. For a recommender, a recipe is a Domain dataset group use case. Only Domain dataset group use cases can be used to create a recommender. For information about use cases see <a href="https://docs.aws.amazon.com/personalize/latest/dg/domain-use-cases.html">Choosing recommender use cases</a>.</p>
    pub fn recipe_arn(&self) -> ::std::option::Option<&str> {
        self.recipe_arn.as_deref()
    }
    /// <p>The configuration details of the recommender.</p>
    pub fn recommender_config(&self) -> ::std::option::Option<&crate::types::RecommenderConfig> {
        self.recommender_config.as_ref()
    }
    /// <p>A list of <a href="https://docs.aws.amazon.com/personalize/latest/dg/tagging-resources.html">tags</a> to apply to the recommender.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateRecommenderInput {
    /// Creates a new builder-style object to manufacture [`CreateRecommenderInput`](crate::operation::create_recommender::CreateRecommenderInput).
    pub fn builder() -> crate::operation::create_recommender::builders::CreateRecommenderInputBuilder {
        crate::operation::create_recommender::builders::CreateRecommenderInputBuilder::default()
    }
}

/// A builder for [`CreateRecommenderInput`](crate::operation::create_recommender::CreateRecommenderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRecommenderInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) recipe_arn: ::std::option::Option<::std::string::String>,
    pub(crate) recommender_config: ::std::option::Option<crate::types::RecommenderConfig>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateRecommenderInputBuilder {
    /// <p>The name of the recommender.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the recommender.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the recommender.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the destination domain dataset group for the recommender.</p>
    /// This field is required.
    pub fn dataset_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the destination domain dataset group for the recommender.</p>
    pub fn set_dataset_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the destination domain dataset group for the recommender.</p>
    pub fn get_dataset_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_group_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the recipe that the recommender will use. For a recommender, a recipe is a Domain dataset group use case. Only Domain dataset group use cases can be used to create a recommender. For information about use cases see <a href="https://docs.aws.amazon.com/personalize/latest/dg/domain-use-cases.html">Choosing recommender use cases</a>.</p>
    /// This field is required.
    pub fn recipe_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recipe_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the recipe that the recommender will use. For a recommender, a recipe is a Domain dataset group use case. Only Domain dataset group use cases can be used to create a recommender. For information about use cases see <a href="https://docs.aws.amazon.com/personalize/latest/dg/domain-use-cases.html">Choosing recommender use cases</a>.</p>
    pub fn set_recipe_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recipe_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the recipe that the recommender will use. For a recommender, a recipe is a Domain dataset group use case. Only Domain dataset group use cases can be used to create a recommender. For information about use cases see <a href="https://docs.aws.amazon.com/personalize/latest/dg/domain-use-cases.html">Choosing recommender use cases</a>.</p>
    pub fn get_recipe_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.recipe_arn
    }
    /// <p>The configuration details of the recommender.</p>
    pub fn recommender_config(mut self, input: crate::types::RecommenderConfig) -> Self {
        self.recommender_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration details of the recommender.</p>
    pub fn set_recommender_config(mut self, input: ::std::option::Option<crate::types::RecommenderConfig>) -> Self {
        self.recommender_config = input;
        self
    }
    /// <p>The configuration details of the recommender.</p>
    pub fn get_recommender_config(&self) -> &::std::option::Option<crate::types::RecommenderConfig> {
        &self.recommender_config
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of <a href="https://docs.aws.amazon.com/personalize/latest/dg/tagging-resources.html">tags</a> to apply to the recommender.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <a href="https://docs.aws.amazon.com/personalize/latest/dg/tagging-resources.html">tags</a> to apply to the recommender.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of <a href="https://docs.aws.amazon.com/personalize/latest/dg/tagging-resources.html">tags</a> to apply to the recommender.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateRecommenderInput`](crate::operation::create_recommender::CreateRecommenderInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_recommender::CreateRecommenderInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_recommender::CreateRecommenderInput {
            name: self.name,
            dataset_group_arn: self.dataset_group_arn,
            recipe_arn: self.recipe_arn,
            recommender_config: self.recommender_config,
            tags: self.tags,
        })
    }
}
