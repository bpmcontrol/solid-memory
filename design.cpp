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
{/*sub-classed by arithmeric, logical operations: max(),+,-,/,*,&&,||,^,~ */};

struct conditional_statement
{/*sub-classed by comparissons, if-else, switch-case */};

class statement_list
{/*holds an ordered list of statements*/};

struct loop_statement
{/*holds a statement_list and a conditional_statement. represents a loop.
  sub-classed by for, while*/};

class statement_hirarchy
{/*holds a description of a function. 
   mapps inputs into statements and forwards the results to other statements.
   Results in a (boolean) value*/};

class code
{/*holds a statement_hirarchy, 
   accepts a statement_list of input_statments and returns the result of the hirarchy when operating on those inputs*/
public:
  code(statement_hirarchy s):_s{s};
  result_type compute(input_ststement ... s){}; /*for debugging*/
private:
  statement_hirarchy _s;
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
reducer<language_type, zkSNARK_type> poker_result_if_first_wins{body};//alternatively, recreate the rules of the poker game, not just positional hirarchy.

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

/*The above example was rather limited, only the winner could avoid revealing his hand, other players had to do so.
 This is an attempt to give a bit more general solution.*/

/*
One possibility is to encode the poker game as a polynmial f(map(x),map(y))=z
 x = hand1
 y = hand2
 map = a mapping from a player's hands to integers s.t. hand1 beats hand2 in a game IFF map(hand1) > map(hand2)
such a mapping is almost trivial since there is a clear order between poker hands eg royal-flush beats pair

Once we have such a polynomial f(), we can use any multiplicative homomorphic encryption (like ElGamal)
Take ElGamal(f) and treat it as f in the generator.
That way the verifier can have the prover prove that he can win without exposing verifier's hand.

*/

/*
Another might be to develop a specific ZK proof for the poker game.

*/
