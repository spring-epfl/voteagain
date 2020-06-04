"""
Polynomials
"""

from functools import reduce
from petlib.bn import Bn


class Polynomial:
    """
    Class to work with polynomials with big numbers from library petlib.

    Implemented with a very restricted usage in mind, so incomplete polinomial class for general use. This allows simple
    operations of polynomials (addition, multiplication and exponantiation by scalar) over Z_p[X].
    """

    def __init__(self, coefficients, modulo):
        """ input: coefficients are in the form a_0, a_1 ...a_n
        """
        self.coefficients = coefficients
        while self.coefficients[-1] == 0 and len(self.coefficients) > 1:
            self.coefficients.pop()
        if type(self.coefficients[0]) == int:
            self.coefficients = [Bn.from_num(i) for i in coefficients]
        self.degree = len(self.coefficients)
        self.modulo = modulo

        if modulo and type(coefficients[0]) != Bn:
            self.coefficients = [Bn.from_num(x) for x in self.coefficients]

    def __add__(self, other):
        """
        Add two polynomials

        Example:
            >>> poly1 = Polynomial([1, 2, 4, 0, 5], 13)
            >>> poly2 = Polynomial([3, 5, 2, 2, 6], 13)
            >>> sum = poly1 + poly2
            >>> sum.coefficients
            [4, 7, 6, 2, 11]

            >>> poly1 = Polynomial([1, 2, 4, 0, 5], 13)
            >>> poly2 = Polynomial([3, 5, 2, 2, 6], 13)
            >>> sum = poly1.to_big_number(modulo=Bn.from_num(5)) + poly2.to_big_number(modulo=Bn.from_num(5))
            >>> sum.coefficients
            [4, 2, 1, 2, 1]
        """
        c1 = self.coefficients
        c2 = other.coefficients
        if self.modulo != other.modulo:
            raise TypeError("Expecting the same modulo out of both polynomials")

        if self.modulo:
            res = [
                t[0].mod_add(t[1], self.modulo) for t in Polynomial.zip_longest(c1, c2)
            ]
        else:
            res = [sum(t) for t in Polynomial.zip_longest(c1, c2)]
        return Polynomial(res, modulo=self.modulo)

    def __sub__(self, other):
        raise NotImplementedError

    def __mul__(self, other):
        """
        Multiply poly

        Example:
            >>> a = Polynomial([1, 2], 13)
            >>> b = Polynomial([3, 3], 13)
            >>> c = a * b
            >>> c.coefficients
            [3, 9, 6]

            >>> cc = a * Polynomial([1, 0], 13)
            >>> cc.coefficients
            [1, 2]

            >>> d = a * 3
            >>> d.coefficients
            [3, 6]

            >>> e = a.to_big_number(Bn.from_num(5))
            >>> f = e * 12
            >>> f.coefficients
            [2, 4]

        """
        if type(other) == Polynomial:
            if self.modulo != other.modulo:
                raise TypeError("Expecting the same modulo out of both polynomials")

        if isinstance(other, Polynomial):
            self_coefficients = self.coefficients
            other_coefficients = other.coefficients
            res = [Bn.from_num(0)] * (
                len(self_coefficients) + len(other_coefficients) - 1
            )
            for self_index, self_coefficient in enumerate(self_coefficients):
                for other_index, other_coefficient in enumerate(other_coefficients):
                    if self.modulo:
                        res[self_index + other_index] = res[
                            self_index + other_index
                        ].mod_add(self_coefficient * other_coefficient, self.modulo)
                    else:
                        res[self_index + other_index] += (
                            self_coefficient * other_coefficient
                        )
        else:
            if self.modulo:
                res = [co.mod_mul(other, self.modulo) for co in self.coefficients]
            else:
                res = [co * other for co in self.coefficients]
        return self.__class__(res, modulo=self.modulo)

    def __pow__(self, power):
        """Not valid for generic power. We only work with powers equal to 0 or 1"""
        if power == 1:
            return self
        elif power == 0:
            return Polynomial([1], modulo=self.modulo)
        else:
            raise ValueError("I'm expecting solely exponents of 0 or 1")

    def to_big_number(self, modulo):
        return Polynomial([Bn.from_num(x) for x in self.coefficients], modulo=modulo)

    def eval(self, point):
        """
        Evaluation of a polynomial

        Example:
            >>> a = Polynomial([1, 2], 7)
            >>> a.eval(2)
            5
            >>> a.eval(3)
            0

        """
        if type(point) == int:
            point = Bn.from_num(point)
        result = Bn.from_num(0)
        for index, coefficient in enumerate(self.coefficients):
            result = result.mod_add(
                coefficient * point.mod_pow(index, self.modulo), self.modulo
            )

        return result

    @staticmethod
    def from_roots(roots, modulo):
        """
        Calculate polynomial from roots

        Example:
            >>> a = Polynomial.from_roots([Bn.from_num(1), Bn.from_num(1)], Bn.from_num(7))
            >>> a.eval(1)
            0

            >>> a = Polynomial.from_roots([1, 2, 3, 3, 4, 5], Bn.from_num(7))
            >>> a.coefficients
            [3, 3, 4, 3, 4, 3, 1]
            >>> a.eval(3)
            0
            >>> a.eval(5)
            0
            >>> a.eval(6)
            3
            >>> order = Bn.from_decimal("52137169930799554717614356857506293818498877974737694294258188871929297414763123103907744062376810056827189091305705434921846346757741920691072816664704800302679217118985586829201265273391676324053123901757229727135241424267879269925766038354395247471758947327023181961662857375240340094119735806654078071568415490759313899749642836086369437285822445537863499850137938649445050574793896418443324129366783154447555359885480360150449533448644540185781810834062108093885074870413486811350157518533438291933078172819638193255100503198570696887787567964374981238663391668092217407521167528524716096503249760795640678745829")
            >>> roots = [Bn.from_decimal('24328626682289136570751536147321521934883276496444403637200791710959330225351187858816284221467749949170967552592192324486105274675745073644298833869379510880054061897691638487850358168087009962101666739301242027780261176000688299869458451077243785452946211728488732020837306283402441986288004713904032620106051702880664181957060410226643578290964003019109479261826859822942513350862756778747973875209750342357933539552875979843312957639435564366361012366291495216191958522420513908595748516389774971404368853339932587005401457667821996489027145786706555858193202229433265835452932244580820310037045608574782179678733') for _ in range(4)]
            >>> big_poly = Polynomial.from_roots(roots, order)
            >>> big_poly.eval(roots[0])
            0

            >>> Polynomial.from_roots([1, 2, 3, 3, 4, 5], Bn.from_num(1000)).coefficients
            [360, 58, 949, 520, 130, 982, 1]
        """
        import itertools

        if type(roots[0]) != Bn:
            roots = [Bn.from_num(a) for a in roots]

        degree_poly = len(roots)
        polynomial = []
        for i in range(0, degree_poly):
            values = list(itertools.combinations(roots, degree_poly - i))
            values = [
                reduce(lambda a, b: a.mod_mul(b, modulo), mults).mod_mul(
                    ((-1) ** (degree_poly - i)), modulo
                )
                for mults in values
            ]
            polynomial.append(reduce(lambda a, b: a.mod_add(b, modulo), values))
        polynomial.append(Bn.from_num(1))
        return Polynomial(polynomial, modulo)

    @staticmethod
    def from_roots_opt(roots, modulo):
        """
                Calculate polynomial from roots, optimally

                Example:
                    >>> a = Polynomial.from_roots_opt([Bn.from_num(1), Bn.from_num(1)], Bn.from_num(7))
                    >>> a.eval(1)
                    0

                    >>> a = Polynomial.from_roots_opt([1, 2, 3, 3, 4, 5], Bn.from_num(7))
                    >>> a.coefficients
                    [3, 3, 4, 3, 4, 3, 1]
                    >>> a.eval(3)
                    0
                    >>> a.eval(5)
                    0
                    >>> a.eval(6)
                    3
                    >>> order = Bn.from_decimal("52137169930799554717614356857506293818498877974737694294258188871929297414763123103907744062376810056827189091305705434921846346757741920691072816664704800302679217118985586829201265273391676324053123901757229727135241424267879269925766038354395247471758947327023181961662857375240340094119735806654078071568415490759313899749642836086369437285822445537863499850137938649445050574793896418443324129366783154447555359885480360150449533448644540185781810834062108093885074870413486811350157518533438291933078172819638193255100503198570696887787567964374981238663391668092217407521167528524716096503249760795640678745829")
                    >>> roots = [Bn.from_decimal('24328626682289136570751536147321521934883276496444403637200791710959330225351187858816284221467749949170967552592192324486105274675745073644298833869379510880054061897691638487850358168087009962101666739301242027780261176000688299869458451077243785452946211728488732020837306283402441986288004713904032620106051702880664181957060410226643578290964003019109479261826859822942513350862756778747973875209750342357933539552875979843312957639435564366361012366291495216191958522420513908595748516389774971404368853339932587005401457667821996489027145786706555858193202229433265835452932244580820310037045608574782179678733') for _ in range(4)]
                    >>> big_poly = Polynomial.from_roots_opt(roots, order)
                    >>> big_poly.eval(roots[0])
                    0

                    >>> Polynomial.from_roots_opt([1, 2, 3, 3, 4, 5], Bn.from_num(1000)).coefficients
                    [360, 58, 949, 520, 130, 982, 1]
                """
        if type(modulo) == int:
            modulo = Bn.from_num(modulo)
        if type(roots[0]) == int:
            roots = [Bn.from_num(a) for a in roots]

        degree_poly = len(roots)
        polynomial = [0] * degree_poly
        polynomial[0] = 1
        for i in range(degree_poly):
            new_poly = []
            new_poly.append((-polynomial[0] * roots[i]).mod(modulo))
            for j in range(1, i + 1):
                new_poly.append(
                    (-polynomial[j] * roots[i] + polynomial[j - 1]).mod(modulo)
                )
            new_poly.append(1)
            polynomial = new_poly

        return Polynomial(polynomial, modulo)

    @staticmethod
    def zip_longest(iter1, iter2, fillchar=Bn.from_num(0)):
        for i in range(max(len(iter1), len(iter2))):
            if i >= len(iter1):
                yield (fillchar, iter2[i])
            elif i >= len(iter2):
                yield (iter1[i], fillchar)
            else:
                yield (iter1[i], iter2[i])
            i += 1


if __name__ == "__main__":
    import doctest

    doctest.testmod()
