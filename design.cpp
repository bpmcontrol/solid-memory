///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                          Authenticity: verify knowledge of the pre-image of this hash:                                                    //
//SHA512(/tmp/preimage.txt)= d3a9f8832456ff68393c6071cebe95e055b45ce323b1dee0479705fbc9b70be5d91947cefd887570bbcbb6c8ccff2d5a94fe71a766d365122f9e453c57faeff6//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////
//'language' to represent claims                                                      //
// a claim to be proven is of the sort f(public_input,secret_input)==TRUE             //
// f() is translated by the user to an object represented in the following 'language' //
// that object is translated by this library to an input of an NP-complete problem    //
// such as QSP for which a zkSNARK is known.                                          //
////////////////////////////////////////////////////////////////////////////////////////

struct input_statement
{/*converts from input for f() to numerical/boolean input accepted by the internal language*/};

struct arithmetic_statement
{/*sub-classed by arithmetic, logical operations: max(),+,-,/,*,&&,||,^,~ */};

struct conditional_statement
{/*sub-classed by comparisons, if-else, switch-case */};

class statement_list
{/*holds an ordered list of statements*/};

struct loop_statement
{/*holds a statement_list and a conditional_statement. represents a loop.
  sub-classed by for, while*/};

class statement_hierarchy
{/*holds a description of a function. 
   maps inputs into statements and forwards the results to other statements.
   Results in a (boolean) value*/};

class code
{/*holds a statement_hierarchy, 
   accepts a statement_list of input_statements and returns the result of the hierarchy when operating on those inputs*/
public:
  code(statement_hierarchy s):_s{s};
  result_type compute(input_statement ... s){}; /*for debugging*/
private:
  statement_hierarchy _s;
};

template<typename language l, class zkSNARK z>
class reducer
{/*takes a code instance in language l and performs a reduction to one of the languages for which a zkSNARK scheme is known
  f(public_input,secret_input)==TRUE iff reducer(f)( reducer(public_input,secret_input )) is in QSP*/
public:
  reducer(code c):{/*translate c from the language l to a representation usable in a zkSNARK of type z*/};
  reduce_input(input_to_code p){/*translate p from input to func() to input to z*/};
private:
  inner_representation _repr; // depends on template parameters
};

//////////////////////
//sources of entropy//
//////////////////////

class entropy
{/*gets a seed, returns random bytes*/};

class public_entropy : public entropy
{/*gets a seed, returns random bytes
  securely exposes the same randomness to all subscribers s.t. all subscribers can verify that they see the same string*/};

class toxic_entropy : public entropy
{/*gets a seed, exposes a read-once (forward iterator) stream of random bytes.
  Seed support is for regulatory purposes, otherwise its a self inflicted gunshot wound to the foot.
  Destroys seed, overwrites used memory, keeps seed in registers,
  uses hardware security modules, combines entropy from multiple non trusting partners.
  All that stuff*/};

//create a code instance for the function 'poker_result_if_first_wins()'
//input: a pair of poker hands p
//output: '1' iff p.first strictly won the round over p.second
//declare inputs as instances of input_statement
input_statement<type_of(p.first)> hand1{};
input_statement<type_of(p.second)> hand2{}; 
//map from cards to numerical values, find maximal value
arithmetic_statement larger{max{hand1, hand2}};
//check that hand1 is the maximal value and that hand2 is not. (to avoid ties)
conditional_statement stmt1{if_equals{larger,hand1}};
conditional_statement stmt2{if_not_equals{larger,hand2}};
conditional_statement stmt3{logical_and{stmt1,stmt2}};
//represent the flow as an object
code body{hand1, hand2, stmt3};
//convert to an object that can be used in a proof
reducer<language_type, zkSNARK_type> poker_result_if_first_wins{body};//alternatively, recreate the rules of the poker game, not just positional hierarchy.

////////////////////////////////////////////////////
//create a keypair <proving key, verification key>//
////////////////////////////////////////////////////

class key_generator
{/*takes a source of entropy, and a reduced 'code' instance,
  produces a keypair proof_key, verify_key */};

key_generator<zkSNARK_type> poker_proof{toxic_entropy{random_seed}, poker_result_if_first_wins};
proving_key = poker_proof.get_proving_key();
verification_key = poker_proof.get_verification_key();
public_input = hand2 /* explanation to come */ ;

////////////////////////////////////////////////////////////////////////////////////
//create a proof from proving key, code for claim, secret input, entropy          //
//This proof can be completely public and marks the end of the part of the winner.//
////////////////////////////////////////////////////////////////////////////////////

proof_static_object<zkSNARK_type> poker_player1_is_the_winner{proving_key,
                                                              poker_result_if_first_wins.reduce_input(public_input),
                                                              poker_result_if_first_wins.reduce_input(hand1)};

//////////////////////////////////////////////
//verify proof using proof, verification key//
//////////////////////////////////////////////

bool did_player1_really_win = verifier<zkSNARK_type>{verification_key, poker_player1_is_the_winner}.verify( poker_result_if_first_wins.reduce_input(public_input) );

/////////////////////////////////////////////
//                 EXPANSION               //
/////////////////////////////////////////////

/*

If we wish to allow player2 to also not reveal his hand, we may employ the following scheme:
  map = a mapping from a player's hands to integers s.t. hand1 beats hand2 in a game IFF map(hand1) > map(hand2)
  E = a public key encryption scheme that is somewhat homomorphic
  'e' = a public encryption key chosen once by verifier and published alongside the generation step.
  f(hand1, hand2) polynomial, f = 0 <=> hand1 wins over hand2 <=> map(hand1) > map(hand2)

Thus, during generation we take f'(x) := f(E(e,hand2),x) 
with E(e,hand2) provided by verifier during generation.

Prover will prove that he computed f'(E(e,hand1)) = E(e,0) without revealing hand1 or learning hand2

Due to homomorphism:
f'(E(e,hand1)) = f((E(e,hand2),E(e,hand1)) //by definition
f((E(e,hand2),E(e,hand1)) = E(e,f(hand1,hand2)) //by homomorphism
Thus:
f'(E(e,hand1)) = E(e,0) <=> E(e,f(hand1,hand2)) = E(e,0)
And if E is half decent (large enough group, which is not an issue with mapping poker hands to ints):
E(e,f(hand1,hand2)) = E(e,0) <=> f(hand1,hand2)) = 0

*/
