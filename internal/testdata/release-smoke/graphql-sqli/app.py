import graphene
from graphene import Mutation, String

class CreateUser(Mutation):
    class Arguments:
        name = String(required=True)

    Output = String

    def mutate(self, info, name):
        query = "INSERT INTO users (name) VALUES ('" + name + "')"
        db.execute(query)
        return "ok"

class Mutations(graphene.ObjectType):
    create_user = CreateUser.Field()

schema = graphene.Schema(mutation=Mutations)
